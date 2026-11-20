package main

// Раздача и приём интернета на ПК (на Android — то же, но через приложение, см. wifishare.go).
//
// Раздача: компьютер принимает устройства своей сети (Wi-Fi роутера, «Мобильного хот-спота»
// Windows) на порту 8282 — по прокси HTTP/SOCKS5. В интернет их соединения открывает сам компьютер:
// без обхода блокировок («Раздача») или с ним («Раздача с обходом блокировок»).
//
// Приём («Подключиться к раздаче»): компьютер подключён к точке доступа телефона, на котором включена
// «Раздача» в Aristocrat NET. Весь трафик программы и системного прокси идёт в прокси телефона,
// и в интернет его отправляет сам телефон — для оператора это трафик телефона, а не раздача.
// Пока идёт приём, программа ничего не открывает напрямую (DNS, IP, списки рекламы — тоже через телефон).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const sharePort = 8282

// ---------------------------------------------------------------------------
// Приём: путь «через телефон».

// phoneLink — прокси раздающего телефона (Upstream для движка).
type phoneLink struct {
	addr string // «IP:8282»
}

const StratPhone = "phone"

func (p *phoneLink) Name() string                 { return StratPhone }
func (p *phoneLink) Enabled() bool                { return true }
func (p *phoneLink) WaitReady(time.Duration) bool { return true }
func (p *phoneLink) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	c, err := socksDial(ctx, p.addr, host, port)
	if err != nil {
		return nil, fmt.Errorf("через телефон: %v", strings.TrimPrefix(err.Error(), "Tor "))
	}
	return c, nil
}

// recvLink — включённый приём (nil — нет). Через него идут и служебные соединения программы.
var recvLink atomic.Pointer[phoneLink]

// netDial — исходящее соединение программы (DNS, внешний IP): при приёме — через телефон.
func netDial(ctx context.Context, network, addr string) (net.Conn, error) {
	if l := recvLink.Load(); l != nil && strings.HasPrefix(network, "tcp") {
		h, p, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		port, _ := strconv.Atoi(p)
		return l.Dial(ctx, h, port)
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
}

// probeShare — на этом адресе работает раздача Aristocrat NET?
func probeShare(host string, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(sharePort)), timeout)
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout + 2*time.Second))
	fmt.Fprintf(c, "GET / HTTP/1.0\r\nHost: %s:%d\r\n\r\n", host, sharePort)
	b, _ := io.ReadAll(io.LimitReader(c, 8192))
	return strings.Contains(string(b), "Aristocrat NET")
}

// findShare ищет раздающее устройство: сначала роутер сети (точка доступа телефона —
// это и есть телефон), потом — все адреса своей сети (раздача с компьютера в домашней сети).
func findShare() (string, error) {
	if gw := defaultGateway(); gw != "" && probeShare(gw, 2*time.Second) {
		return gw, nil
	}
	var cands []string
	for _, ip := range lanAddrs() {
		v4 := net.ParseIP(ip).To4()
		for i := 1; i < 255; i++ {
			if byte(i) == v4[3] {
				continue
			}
			cands = append(cands, fmt.Sprintf("%d.%d.%d.%d", v4[0], v4[1], v4[2], i))
		}
	}
	if len(cands) == 0 {
		return "", errors.New("компьютер не подключён к сети: подключитесь к сети, где раздают интернет")
	}
	found := make(chan string, 1)
	sem := make(chan struct{}, 96)
	var wg sync.WaitGroup
	for _, h := range cands {
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			if probeShare(h, 800*time.Millisecond) {
				select {
				case found <- h:
				default:
				}
			}
		}(h)
	}
	go func() { wg.Wait(); close(found) }()
	if h, ok := <-found; ok {
		return h, nil
	}
	return "", errors.New("раздача не найдена: на раздающем устройстве включите «Раздачу» в Aristocrat NET (на телефоне — и точку доступа) и подключите к его сети этот компьютер")
}

// lanAddrs — свои адреса в домашних сетях (192.168.x.x, 10.x.x.x, 172.16–31.x.x).
func lanAddrs() []string {
	var out []string
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		n := strings.ToLower(ifc.Name)
		if strings.Contains(n, "virtual") || strings.Contains(n, "vmware") || strings.Contains(n, "vbox") ||
			strings.HasPrefix(n, "docker") || strings.HasPrefix(n, "veth") || strings.HasPrefix(n, "br-") ||
			strings.Contains(n, "wsl") || strings.Contains(n, "hyper-v") || strings.HasPrefix(n, "tun") {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && ipn.IP.IsPrivate() {
				out = append(out, ipn.IP.To4().String())
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Состояние раздачи и приёма.

type lanState struct {
	mu        sync.Mutex
	shareLn   net.Listener
	shareEng  *Engine
	bypass    bool
	recvHost  string
	recvErr   string
	recvOwnOn bool // приём сам включил прокси программы (выключить при остановке)
	recvSysPx bool // приём сам включил системный прокси
	recvStop  chan struct{}
}

var lan lanState

func (a *App) shareOn() (on, bypass bool) {
	lan.mu.Lock()
	defer lan.mu.Unlock()
	return lan.shareLn != nil, lan.bypass
}

// shareStart — раздать интернет устройствам своей сети.
func (a *App) shareStart(bypass bool) error {
	if recvLink.Load() != nil {
		return errors.New("сначала выключите приём интернета с телефона")
	}
	a.shareStop()
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(sharePort))
	if err != nil {
		return fmt.Errorf("порт %d занят — раздача уже запущена другой программой", sharePort)
	}
	allowFirewall(sharePort)
	eng := NewEngine(a.res, func(string, ...any) {})
	eng.Plain.Store(!bypass)
	if bypass {
		route := a.settings().Route
		if route == RouteDPI || RouteNames[route] == "" {
			route = RouteAuto
		}
		eng.Route.Store(route)
		eng.Mode.Store(a.settings().Mode)
		eng.Tor, eng.Warp, eng.Local, eng.Direct = a.eng.Tor, a.eng.Warp, a.eng.Local, a.eng.Direct
	}
	eng.Ads = a.ads
	eng.ServeLAN(ln)
	lan.mu.Lock()
	lan.shareLn, lan.shareEng, lan.bypass = ln, eng, bypass
	lan.mu.Unlock()
	a.updSharing()
	if bypass {
		go a.startUpstreams(false)
	}
	mode := "без обхода блокировок"
	if bypass {
		mode = "с обходом блокировок"
	}
	a.logf("Раздача включена (%s): адрес %s, порт %d", mode, strings.Join(lanAddrs(), ", "), sharePort)
	return nil
}

func (a *App) shareStop() {
	lan.mu.Lock()
	ln := lan.shareLn
	lan.shareLn, lan.shareEng, lan.bypass = nil, nil, false
	lan.mu.Unlock()
	if ln != nil {
		ln.Close()
		a.updSharing()
		a.logf("Раздача выключена")
	}
}

// updSharing — нужен ли полный обход (WARP и Tor) кому-то, кроме самого компьютера.
func (a *App) updSharing() {
	lan.mu.Lock()
	lanB := lan.shareLn != nil && lan.bypass
	lan.mu.Unlock()
	a.sharing.Store(lanB || (a.dev != nil && (a.dev.On() || a.dev.ExitOn())))
}

func (a *App) recvOn() (on bool, host, errText string) {
	lan.mu.Lock()
	defer lan.mu.Unlock()
	return recvLink.Load() != nil, lan.recvHost, lan.recvErr
}

// recvStart — подключиться к раздаче: найти её и пустить через неё весь трафик.
func (a *App) recvStart() error {
	if on, _ := a.shareOn(); on {
		return errors.New("сначала выключите раздачу с этого компьютера")
	}
	host, err := findShare()
	if err != nil {
		lan.mu.Lock()
		lan.recvErr = err.Error()
		lan.mu.Unlock()
		return err
	}
	link := &phoneLink{addr: net.JoinHostPort(host, strconv.Itoa(sharePort))}
	recvLink.Store(link)
	a.eng.setForced(link)
	forgetIP()
	stop := make(chan struct{})
	lan.mu.Lock()
	lan.recvHost, lan.recvErr, lan.recvStop = host, "", stop
	lan.mu.Unlock()
	a.startUpstreams(false) // WARP и Tor не нужны: всё идёт через телефон
	if !a.eng.Running() {
		if err := a.enable(); err != nil {
			a.recvStop()
			return err
		}
		lan.mu.Lock()
		lan.recvOwnOn = true
		lan.mu.Unlock()
	}
	if !a.settings().SysProxy {
		port := a.settings().Port
		if err := SetSystemProxy(port); err == nil {
			lan.mu.Lock()
			lan.recvSysPx = true
			lan.mu.Unlock()
		}
	}
	go a.watchRecv(host, stop)
	a.logf("Подключено к раздаче %s: весь трафик идёт через неё", host)
	return nil
}

// watchRecv следит, отвечает ли телефон.
func (a *App) watchRecv(host string, stop chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case <-time.After(10 * time.Second):
		}
		msg := ""
		if !probeShare(host, 3*time.Second) {
			msg = "раздача " + host + " не отвечает: проверьте сеть и «Раздачу» на раздающем устройстве"
		}
		lan.mu.Lock()
		changed := lan.recvErr != msg && lan.recvStop == stop
		if lan.recvStop == stop {
			lan.recvErr = msg
		}
		lan.mu.Unlock()
		if changed && msg != "" {
			a.logf("%s", msg)
		}
	}
}

// clearRecv выключает приём, не трогая сам прокси (для disable()).
func (a *App) clearRecv() (ownOn, sysPx bool) {
	if recvLink.Swap(nil) == nil {
		return false, false
	}
	a.eng.setForced(nil)
	forgetIP()
	lan.mu.Lock()
	ownOn, sysPx = lan.recvOwnOn, lan.recvSysPx
	if lan.recvStop != nil {
		close(lan.recvStop)
	}
	lan.recvHost, lan.recvErr, lan.recvOwnOn, lan.recvSysPx, lan.recvStop = "", "", false, false, nil
	lan.mu.Unlock()
	a.logf("Приём интернета с телефона выключен")
	return ownOn, sysPx
}

func (a *App) recvStop() {
	ownOn, sysPx := a.clearRecv()
	switch {
	case ownOn:
		a.disable()
	case sysPx:
		UnsetSystemProxy(a.settings().Port)
		go a.startUpstreams(false)
	default:
		go a.startUpstreams(false)
	}
}

// summary — что делает программа сейчас (строка под кнопкой).
func (a *App) summary() string {
	if on, host, _ := a.recvOn(); on {
		return "Подключено к раздаче " + host
	}
	return routeSummary(a.settings())
}

// lanStateMap — для веб-интерфейса.
func (a *App) lanStateMap() map[string]any {
	on, bypass := a.shareOn()
	r, host, rerr := a.recvOn()
	return map[string]any{
		"share": on, "bypass": bypass, "addrs": lanAddrs(), "port": sharePort,
		"recv": r, "recv_host": host, "recv_err": rerr,
	}
}

// forgetIP — внешний IP сменился (приём включён или выключен): узнать заново.
func forgetIP() {
	ipCache.Lock()
	ipCache.exp = time.Time{}
	ipCache.Unlock()
}
