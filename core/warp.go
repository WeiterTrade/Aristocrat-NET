package main

// Cloudflare WARP — бесплатный запасной путь без своих серверов.
//
// Программа сама регистрирует бесплатный аккаунт WARP (как официальное приложение 1.1.1.1),
// поднимает WireGuard-туннель до ближайшего узла Cloudflare внутри себя (wireguard-go +
// сетевой стек gVisor, без драйверов и прав администратора) и открывает через него
// соединения. Сайты видят IP-адрес Cloudflare, а не ваш; провайдер видит только
// зашифрованный UDP до Cloudflare.
//
// Против блокировки WireGuard по сигнатуре (Россия) перед каждым рукопожатием
// отправляется несколько пакетов со случайным мусором (приём AmneziaWG) — сервер
// Cloudflare их игнорирует, а DPI не узнаёт начало соединения. Узлы и порты
// перебираются, пока не найдётся рабочий.

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	netstack "obhod/internal/wgnetstack"
)

const (
	warpAPI     = "https://api.cloudflareclient.com/v0a2158"
	warpMTU     = 1280
	warpJunkMin = 40
	warpJunkMax = 70
	warpJunkCnt = 4
)

var (
	warpPrefixes = []string{"162.159.192.", "162.159.193.", "162.159.195.", "188.114.96.", "188.114.97.", "188.114.98.", "188.114.99."}
	warpPorts    = []int{2408, 500, 1701, 4500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942,
		943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371, 2506, 3138,
		3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886}
)

// warpAccount — данные бесплатного аккаунта (хранятся в warp.json в папке программы).
type warpAccount struct {
	ID         string `json:"id"`
	Token      string `json:"token"`
	PrivateKey string `json:"private_key"` // base64
	PeerPublic string `json:"peer_public"` // base64
	V4         string `json:"v4"`
	V6         string `json:"v6"`
	ClientID   string `json:"client_id"` // base64, 3 байта «reserved»
	Endpoint   string `json:"endpoint"`  // последний рабочий узел
}

// Warp — туннель WARP. Реализует Upstream.
type Warp struct {
	// DialTLS — TLS-соединение к API Cloudflare с обходом DPI (задаёт приложение).
	DialTLS func(ctx context.Context, host string, port int) (net.Conn, error)

	mu       sync.Mutex
	dir      string
	logf     func(string, ...any)
	status   string // off | starting | ready | error
	errMsg   string
	endpoint string
	ready    chan struct{}
	gen      int // номер запуска: старые горутины по нему понимают, что их остановили
	dev      *device.Device
	tnet     *netstack.Net
	v4       netip.Addr
}

func NewWarp(dir string, logf func(string, ...any)) *Warp {
	return &Warp{dir: dir, logf: logf, status: "off", ready: make(chan struct{})}
}

func (w *Warp) Name() string { return StratWarp }

// label — как называть туннель в журнале.
func (w *Warp) label() string { return "WARP" }

func (w *Warp) Enabled() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status == "starting" || w.status == "ready"
}

// Status — состояние для интерфейса: off | starting | ready | error и текст ошибки.
func (w *Warp) Status() (string, string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status, w.errMsg
}

// Endpoint — узел Cloudflare, через который идёт туннель.
func (w *Warp) Endpoint() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.endpoint
}

// WaitReady ждёт подключения не дольше d (состояние перепроверяется каждые полсекунды,
// чтобы переподключение туннеля не оставляло ожидающих на старом запуске).
func (w *Warp) WaitReady(d time.Duration) bool {
	end := time.Now().Add(d)
	for {
		w.mu.Lock()
		ch, st := w.ready, w.status
		w.mu.Unlock()
		if st == "ready" {
			return true
		}
		left := time.Until(end)
		if st != "starting" || left <= 0 {
			return false
		}
		if left > 500*time.Millisecond {
			left = 500 * time.Millisecond
		}
		select {
		case <-ch:
		case <-time.After(left):
		}
	}
}

// Start запускает подключение в фоне (повторный вызов при работающем WARP ничего не делает).
func (w *Warp) Start() {
	w.mu.Lock()
	if w.status == "starting" || w.status == "ready" {
		w.mu.Unlock()
		return
	}
	w.gen++
	gen := w.gen
	w.status, w.errMsg = "starting", ""
	w.ready = make(chan struct{})
	w.mu.Unlock()
	go w.run(gen)
}

func (w *Warp) Stop() {
	w.mu.Lock()
	w.gen++
	dev := w.dev
	w.dev, w.tnet = nil, nil
	if w.status != "off" {
		w.status, w.errMsg = "off", ""
	}
	w.mu.Unlock()
	if dev != nil {
		dev.Close()
	}
}

func (w *Warp) alive(gen int) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.gen == gen
}

func (w *Warp) fail(gen int, msg string) {
	w.mu.Lock()
	if w.gen == gen {
		w.status, w.errMsg = "error", msg
	}
	w.mu.Unlock()
	w.logf("%s: %s", w.label(), msg)
}

func (w *Warp) run(gen int) {
	var acc *warpAccount
	for attempt := 0; w.alive(gen); attempt++ {
		if acc == nil {
			a, err := w.account()
			if err != nil {
				w.fail(gen, "не удалось получить бесплатный аккаунт WARP: "+plainErr(err))
				if !w.sleepAlive(gen, time.Minute) { // сеть могла ещё не подняться — повторим
					return
				}
				continue
			}
			acc = a
		}
		dev, tnet, ep, err := w.connect(acc, gen)
		if err != nil {
			if !w.alive(gen) {
				return
			}
			if attempt == 0 {
				w.logf("WARP: %v — пробую ещё", err)
			}
			if attempt >= 2 {
				// Пока WARP недоступен, сайты не ждут его (статус «ошибка»), а попытки идут в фоне.
				w.fail(gen, err.Error()+". Возможно, провайдер блокирует WARP")
				if !w.sleepAlive(gen, 2*time.Minute) {
					return
				}
				continue
			}
			time.Sleep(3 * time.Second)
			continue
		}
		w.mu.Lock()
		if w.gen != gen {
			w.mu.Unlock()
			dev.Close()
			return
		}
		w.dev, w.tnet, w.endpoint = dev, tnet, ep
		w.v4, _ = netip.ParseAddr(acc.V4)
		w.status, w.errMsg = "ready", ""
		select {
		case <-w.ready:
		default:
			close(w.ready)
		}
		w.mu.Unlock()
		w.logf("WARP подключён (узел %s)", ep)
		if acc.Endpoint != ep {
			acc.Endpoint = ep
			_ = w.saveAccount(acc)
		}
		// Следим за туннелем: если рукопожатия давно не было — переподключаемся.
		if !w.watch(dev, gen) {
			return
		}
		w.logf("WARP: связь с узлом %s потеряна, переподключаюсь", ep)
		w.mu.Lock()
		if w.gen == gen {
			w.dev, w.tnet = nil, nil
			w.status = "starting"
			w.ready = make(chan struct{})
		}
		w.mu.Unlock()
		dev.Close()
		attempt = -1
	}
}

func (w *Warp) sleepAlive(gen int, d time.Duration) bool {
	for end := time.Now().Add(d); time.Now().Before(end); {
		time.Sleep(time.Second)
		if !w.alive(gen) {
			return false
		}
	}
	return true
}

// plainErr убирает из ошибки HTTP-клиента служебное «Post "https://…":».
func plainErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}

// watch возвращает true, если туннель «умер» и нужно переподключиться; false — WARP остановили.
func (w *Warp) watch(dev *device.Device, gen int) bool {
	for {
		time.Sleep(20 * time.Second)
		if !w.alive(gen) {
			return false
		}
		if age := handshakeAge(dev); age > 4*time.Minute {
			return true
		}
	}
}

// handshakeAge — сколько прошло с последнего рукопожатия (очень много, если его не было).
func handshakeAge(dev *device.Device) time.Duration {
	s, err := dev.IpcGet()
	if err != nil {
		return 1 << 62
	}
	for _, l := range strings.Split(s, "\n") {
		if v, ok := strings.CutPrefix(l, "last_handshake_time_sec="); ok {
			sec, _ := strconv.ParseInt(v, 10, 64)
			if sec == 0 {
				return 1 << 62
			}
			return time.Since(time.Unix(sec, 0))
		}
	}
	return 1 << 62
}

// candidates — узлы для перебора: сначала последний рабочий и стандартный, затем случайные.
func warpCandidates(saved string, n int) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	add(saved)
	add("162.159.192.1:2408")
	add("162.159.193.10:2408")
	add("188.114.97.3:2408")
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	for len(out) < n {
		ip := warpPrefixes[r.Intn(len(warpPrefixes))] + strconv.Itoa(1+r.Intn(254))
		add(net.JoinHostPort(ip, strconv.Itoa(warpPorts[r.Intn(len(warpPorts))])))
	}
	return out
}

// connect перебирает узлы пачками и возвращает первый, с которым прошло рукопожатие.
func (w *Warp) connect(acc *warpAccount, gen int) (*device.Device, *netstack.Net, string, error) {
	type result struct {
		dev  *device.Device
		tnet *netstack.Net
		ep   string
	}
	cands := warpCandidates(acc.Endpoint, 36)
	const batch = 6
	var lastErr error
	for i := 0; i < len(cands) && w.alive(gen); i += batch {
		end := i + batch
		if end > len(cands) {
			end = len(cands)
		}
		ch := make(chan *result, end-i)
		var emu sync.Mutex
		for _, ep := range cands[i:end] {
			go func(ep string) {
				dev, tnet, err := w.probe(acc, ep)
				if err != nil {
					emu.Lock()
					lastErr = err
					emu.Unlock()
					ch <- nil
					return
				}
				ch <- &result{dev, tnet, ep}
			}(ep)
		}
		// Берём первый ответивший узел, не дожидаясь остальных; лишние туннели закрываем.
		var best *result
		left := end - i
		for ; left > 0; left-- {
			if r := <-ch; r != nil {
				best = r
				left--
				break
			}
		}
		go func(left int) {
			for ; left > 0; left-- {
				if r := <-ch; r != nil {
					r.dev.Close()
				}
			}
		}(left)
		if best != nil {
			return best.dev, best.tnet, best.ep, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("узлы Cloudflare не отвечают")
	}
	return nil, nil, "", fmt.Errorf("нет связи с узлами WARP: %v", lastErr)
}

// probe поднимает туннель к одному узлу и ждёт рукопожатия не дольше 4 секунд.
func (w *Warp) probe(acc *warpAccount, ep string) (*device.Device, *netstack.Net, error) {
	var addrs []netip.Addr
	for _, s := range []string{acc.V4, acc.V6} {
		if a, err := netip.ParseAddr(strings.Split(s, "/")[0]); err == nil {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		return nil, nil, errors.New("в настройках туннеля нет адреса")
	}
	dns := []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("1.0.0.1")}
	mtu := warpMTU
	tdev, tnet, err := netstack.CreateNetTUN(addrs, dns, mtu)
	if err != nil {
		return nil, nil, err
	}
	reserved := [3]byte{}
	if b, err := base64.StdEncoding.DecodeString(acc.ClientID); err == nil && len(b) >= 3 {
		copy(reserved[:], b[:3])
	}
	bind := &warpBind{Bind: conn.NewStdNetBind(), reserved: reserved}
	dev := device.NewDevice(tdev, bind, device.NewLogger(device.LogLevelSilent, ""))
	priv, _ := base64.StdEncoding.DecodeString(acc.PrivateKey)
	peer, _ := base64.StdEncoding.DecodeString(acc.PeerPublic)
	cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=25\n"+
		"allowed_ip=0.0.0.0/0\nallowed_ip=::/0\n", hex.EncodeToString(priv), hex.EncodeToString(peer), ep)
	if err := dev.IpcSet(cfg); err != nil {
		dev.Close()
		return nil, nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, nil, err
	}
	// Подталкиваем рукопожатие трафиком.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		if c, err := tnet.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("1.1.1.1:80")); err == nil {
			c.Close()
		}
	}()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(150 * time.Millisecond)
		if handshakeAge(dev) < time.Minute {
			return dev, tnet, nil
		}
	}
	dev.Close()
	return nil, nil, fmt.Errorf("узел %s не ответил", ep)
}

// Dial открывает TCP-соединение через WARP. DNS тоже идёт через туннель (1.1.1.1).
func (w *Warp) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	w.mu.Lock()
	tnet, st := w.tnet, w.status
	w.mu.Unlock()
	if tnet == nil || st != "ready" {
		return nil, errors.New(w.label() + " не подключён")
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		addrs = []netip.Addr{a}
	} else {
		type lr struct {
			names []string
			err   error
		}
		ch := make(chan lr, 1)
		go func() {
			n, err := tnet.LookupHost(host)
			ch <- lr{n, err}
		}()
		var names []string
		select {
		case r := <-ch:
			if r.err != nil {
				return nil, fmt.Errorf("DNS через туннель: %v", r.err)
			}
			names = r.names
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		for _, n := range names {
			if a, err := netip.ParseAddr(n); err == nil {
				addrs = append(addrs, a)
			}
		}
	}
	// Сначала IPv4: он у WARP работает надёжнее.
	sortV4First(addrs)
	var lastErr error = errors.New("адрес не найден")
	for i, a := range addrs {
		if i >= 3 {
			break
		}
		c, err := tnet.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(a.Unmap(), uint16(port)))
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func sortV4First(a []netip.Addr) {
	j := 0
	for i := range a {
		if a[i].Unmap().Is4() {
			a[i], a[j] = a[j], a[i]
			j++
		}
	}
}

// ListenUDP — UDP-сокет внутри туннеля (только IPv4).
func (w *Warp) ListenUDP() (net.PacketConn, error) {
	w.mu.Lock()
	tnet, v4 := w.tnet, w.v4
	w.mu.Unlock()
	if tnet == nil || !v4.IsValid() {
		return nil, errors.New("WARP не подключён")
	}
	c, err := tnet.ListenUDP(&net.UDPAddr{IP: v4.AsSlice()})
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ---------------------------------------------------------------------------
// Аккаунт

func (w *Warp) accountPath() string { return filepath.Join(w.dir, "warp.json") }

func (w *Warp) saveAccount(a *warpAccount) error {
	b, _ := json.MarshalIndent(a, "", "  ")
	_ = os.MkdirAll(w.dir, 0o700)
	return os.WriteFile(w.accountPath(), b, 0o600)
}

func (w *Warp) account() (*warpAccount, error) {
	if b, err := os.ReadFile(w.accountPath()); err == nil {
		var a warpAccount
		if json.Unmarshal(b, &a) == nil && a.PrivateKey != "" && a.PeerPublic != "" && a.V4 != "" {
			return &a, nil
		}
	}
	w.logf("WARP: регистрирую бесплатный аккаунт Cloudflare…")
	var a *warpAccount
	var err error
	for i := 0; i < 3; i++ {
		if a, err = w.register(); err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		return nil, err
	}
	if err := w.saveAccount(a); err != nil {
		w.logf("WARP: не удалось сохранить аккаунт: %v", err)
	}
	return a, nil
}

// ResetAccount удаляет сохранённый аккаунт (при следующем запуске будет новый).
func (w *Warp) ResetAccount() { _ = os.Remove(w.accountPath()) }

type warpRegResp struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Config struct {
		ClientID string `json:"client_id"`
		Peers    []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4   string `json:"v4"`
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
	} `json:"config"`
}

func (w *Warp) httpClient() *http.Client {
	tr := &http.Transport{
		Proxy:               nil,
		TLSHandshakeTimeout: 15 * time.Second,
		ForceAttemptHTTP2:   false,
	}
	if w.DialTLS != nil {
		tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := splitHostPort(addr, "443")
			if err != nil {
				return nil, err
			}
			return w.DialTLS(ctx, host, port)
		}
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

func warpRequest(method, url, token string, body any) (*http.Request, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "okhttp/3.12.1")
	req.Header.Set("CF-Client-Version", "a-6.11-2223")
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req, nil
}

func (w *Warp) register() (*warpAccount, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	body := map[string]any{
		"key":           pub,
		"install_id":    "",
		"fcm_token":     "",
		"tos":           time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"model":         "PC",
		"serial_number": "",
		"type":          "Android",
		"locale":        "ru_RU",
	}
	req, err := warpRequest("POST", warpAPI+"/reg", "", body)
	if err != nil {
		return nil, err
	}
	cl := w.httpClient()
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("сервер Cloudflare ответил %d", resp.StatusCode)
	}
	var r warpRegResp
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("непонятный ответ Cloudflare: %v", err)
	}
	if len(r.Config.Peers) == 0 || r.Config.Interface.Addresses.V4 == "" {
		return nil, errors.New("в ответе Cloudflare нет настроек туннеля")
	}
	a := &warpAccount{
		ID: r.ID, Token: r.Token,
		PrivateKey: base64.StdEncoding.EncodeToString(priv.Bytes()),
		PeerPublic: r.Config.Peers[0].PublicKey,
		V4:         r.Config.Interface.Addresses.V4,
		V6:         r.Config.Interface.Addresses.V6,
		ClientID:   r.Config.ClientID,
	}
	// Включаем WARP на аккаунте (на новых аккаунтах он и так включён — ошибку не считаем).
	if r.ID != "" && r.Token != "" {
		if req, err := warpRequest("PATCH", warpAPI+"/reg/"+r.ID, r.Token, map[string]any{"warp_enabled": true}); err == nil {
			if resp, err := cl.Do(req); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
	}
	w.logf("WARP: аккаунт получен")
	return a, nil
}

// ---------------------------------------------------------------------------
// Транспорт: «reserved»-байты WARP и мусорные пакеты перед рукопожатием.

type warpBind struct {
	conn.Bind
	reserved [3]byte
}

func (b *warpBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, p, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	out := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		fn := fn
		out[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := fn(packets, sizes, eps)
			for j := 0; j < n; j++ {
				if sizes[j] >= 4 {
					packets[j][1], packets[j][2], packets[j][3] = 0, 0, 0
				}
			}
			return n, err
		}
	}
	return out, p, nil
}

func (b *warpBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	for _, buf := range bufs {
		if len(buf) >= 4 {
			copy(buf[1:4], b.reserved[:])
		}
		// Начало рукопожатия (тип 1, 148 байт) — сначала мусор, чтобы DPI не узнал WireGuard.
		if len(buf) == 148 && buf[0] == 1 {
			for i := 0; i < warpJunkCnt; i++ {
				j := make([]byte, warpJunkMin+mrand.Intn(warpJunkMax-warpJunkMin+1))
				_, _ = rand.Read(j)
				j[0] |= 0x80 // не похоже ни на один тип пакета WireGuard — сервер просто отбросит
				_ = b.Bind.Send([][]byte{j}, ep)
			}
		}
	}
	return b.Bind.Send(bufs, ep)
}
