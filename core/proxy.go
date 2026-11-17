package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Engine — локальный прокси с обходом DPI.
type Engine struct {
	Resolver  *Resolver
	Mode      atomic.Value // "auto" или конкретный метод обхода DPI
	Route     atomic.Value // RouteAuto | RouteDPI | RouteTor
	Tor       *Tor
	Warp      *Warp
	Local     *Local        // российские и казахстанские сайты — напрямую; Spotify в России — через Tor
	Ads       *AdBlock      // блокировка рекламы (nil — выключена)
	Dev       *DevLink      // «через разработчика» (nil — в сборке нет кода подключения)
	Share     *ShareAuth    // раздача (сборка разработчика): вход по логину SOCKS5, учёт клиентов
	names     dnsNames      // адрес → имя сайта (по ответам нашего DNS, см. dnsserver.go)
	BlockQUIC bool          // не пропускать UDP/443: браузеры и приложения переходят на TCP, где работает обход DPI
	Timeout   time.Duration // ожидание ответа сервера на каждый метод
	TorWait   time.Duration // сколько ждать подключения Tor при фолбэке

	DialTimeout time.Duration

	mu      sync.Mutex
	learned map[string]string // домен → сработавший метод
	blocked map[string]string // домен → причина (последняя неудача)
	onLearn func()
	logf    func(string, ...any)

	ln     net.Listener
	conns  atomic.Int64
	total  atomic.Int64
	fixed  atomic.Int64 // соединения, где обход понадобился
	selfPt int
}

func NewEngine(r *Resolver, logf func(string, ...any)) *Engine {
	e := &Engine{Resolver: r, Timeout: 3 * time.Second, TorWait: 90 * time.Second, DialTimeout: 4 * time.Second,
		learned: map[string]string{}, blocked: map[string]string{}, logf: logf}
	e.Mode.Store("auto")
	e.Route.Store(RouteAuto)
	return e
}

func (e *Engine) Learned() map[string]string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]string, len(e.learned))
	for k, v := range e.learned {
		out[k] = v
	}
	return out
}

func (e *Engine) Blocked() map[string]string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]string, len(e.blocked))
	for k, v := range e.blocked {
		out[k] = v
	}
	return out
}

func (e *Engine) SetLearned(m map[string]string) {
	e.mu.Lock()
	e.learned = map[string]string{}
	for k, v := range m {
		if validStrategy(v) {
			e.learned[k] = v
		}
	}
	e.mu.Unlock()
}

func (e *Engine) Forget(host string) {
	e.mu.Lock()
	if host == "" {
		e.learned = map[string]string{}
		e.blocked = map[string]string{}
	} else {
		delete(e.learned, host)
		delete(e.blocked, host)
	}
	e.mu.Unlock()
	if e.onLearn != nil {
		e.onLearn()
	}
}

func (e *Engine) Running() bool { e.mu.Lock(); defer e.mu.Unlock(); return e.ln != nil }

func (e *Engine) Start(port int) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ln != nil {
		return nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return fmt.Errorf("порт %d уже занят — скорее всего, запущена ещё одна копия «Обхода» "+
			"(закройте её кнопкой «Выход» или завершите Obhod.exe в Диспетчере задач) либо другая программа; "+
			"можно сменить порт в настройках", port)
	}
	e.ln, e.selfPt = ln, port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go e.handle(c)
		}
	}()
	e.logf("Прокси запущен на 127.0.0.1:%d", port)
	return nil
}

func (e *Engine) Stop() {
	e.mu.Lock()
	ln := e.ln
	e.ln = nil
	e.mu.Unlock()
	if ln != nil {
		ln.Close()
		e.logf("Прокси остановлен")
	}
}

// Маршрутизация.
const (
	RouteAuto = "auto" // обход DPI, при неудаче — WARP/Tor
	RouteDPI  = "dpi"  // только обход DPI
	RouteTor  = "tor"  // всё через Tor
	RouteWarp = "warp" // всё через Cloudflare WARP (другой IP)
	// RouteDev — всё через компьютер разработчика (см. devlink.go)
)

var RouteNames = map[string]string{
	RouteAuto: "Авто: обход DPI, при блокировке — WARP или Tor",
	RouteDPI:  "Только обход DPI",
	RouteWarp: "Всё через WARP (смена IP)",
	RouteTor:  "Всё через Tor",
}

// Upstream — запасной путь для тяжёлых случаев (блокировка по IP, подмена DNS):
// Cloudflare WARP или Tor.
type Upstream interface {
	Name() string // StratWarp | StratTor
	Enabled() bool
	WaitReady(d time.Duration) bool
	Dial(ctx context.Context, host string, port int) (net.Conn, error)
}

func (e *Engine) route() string {
	r, _ := e.Route.Load().(string)
	if r == "" {
		return RouteAuto
	}
	return r
}

func (e *Engine) torOn() bool  { return e.Tor != nil && e.Tor.Enabled() }
func (e *Engine) warpOn() bool { return e.Warp != nil && e.Warp.Enabled() }

// upstreams — запасные пути по порядку для текущего режима.
func (e *Engine) upstreams() []Upstream {
	var out []Upstream
	switch e.route() {
	case RouteDPI:
	case RouteDev:
		if e.Dev != nil && e.Dev.WaitReady(0) {
			out = append(out, e.Dev)
		}
		if e.warpOn() {
			out = append(out, e.Warp)
		}
		if e.torOn() {
			out = append(out, e.Tor)
		}
	case RouteTor:
		if e.torOn() {
			out = append(out, e.Tor)
		}
	case RouteWarp:
		if e.warpOn() {
			out = append(out, e.Warp)
		}
	default:
		if e.warpOn() {
			out = append(out, e.Warp)
		}
		if e.torOn() {
			out = append(out, e.Tor)
		}
	}
	return out
}

func (e *Engine) upstreamByName(name string) Upstream {
	switch {
	case name == StratTor && e.torOn():
		return e.Tor
	case name == StratWarp && e.warpOn():
		return e.Warp
	case name == StratDev && e.Dev != nil && e.Dev.WaitReady(0):
		return e.Dev
	}
	return nil
}

// viaFirst — путь, по которому идти сразу, не пытаясь напрямую (nil — напрямую).
func (e *Engine) viaFirst(host string) (Upstream, error) {
	if strings.HasSuffix(host, ".onion") {
		if e.torOn() {
			return e.Tor, nil
		}
		return nil, errors.New("сайты .onion открываются только через Tor — включите Tor в настройках")
	}
	if isLocalAddr(host) {
		return nil, nil
	}
	// Сервис закрыт для страны пользователя (Spotify в России) — через Tor в любом режиме.
	if e.Local.NeedsForeignIP(host) && e.torOn() {
		return e.Tor, nil
	}
	// Российские и казахстанские сайты — напрямую, с настоящим IP, в любом режиме.
	if e.Local.Direct(host) {
		return nil, nil
	}
	// YouTube в России — с российским IP (без рекламы): напрямую с обходом замедления
	// или, в режиме «Всё через WARP», через WARP — но никогда через Tor.
	if e.Local.HomeIPOnly(host) {
		if e.route() == RouteWarp && e.warpOn() {
			return e.Warp, nil
		}
		return nil, nil
	}
	switch e.route() {
	case RouteDev:
		// Через разработчика, пока его компьютер отвечает; иначе — как в «Авто».
		if e.Dev != nil && e.Dev.WaitReady(0) {
			return e.Dev, nil
		}
	case RouteTor:
		if !e.torOn() {
			return nil, errors.New("Tor не запущен")
		}
		return e.Tor, nil
	case RouteWarp:
		if !e.warpOn() {
			return nil, errors.New("WARP не запущен")
		}
		return e.Warp, nil
	case RouteDPI:
		return nil, nil
	}
	e.mu.Lock()
	l := e.learned[host]
	e.mu.Unlock()
	// Сайт уже открывался только через запасной путь — сразу туда, но только если путь работает
	// прямо сейчас (иначе пробуем напрямую: вдруг блокировку сняли).
	if u := e.upstreamByName(l); u != nil && u.WaitReady(0) {
		return u, nil
	}
	return nil, nil
}

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}
var benchmark = &net.IPNet{IP: net.IPv4(198, 18, 0, 0), Mask: net.CIDRMask(15, 32)}

// isLocalAddr — локальные и служебные адреса: в Tor/WARP их отправлять бессмысленно.
func isLocalAddr(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".local") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() ||
		ip.IsMulticast() || cgnat.Contains(ip) || benchmark.Contains(ip)
}

// upDial подключается через один запасной путь, дождавшись его готовности.
func (e *Engine) upDial(u Upstream, host string, port int) (net.Conn, error) {
	wait := e.TorWait
	if u.Name() == StratWarp {
		wait = 20 * time.Second
	}
	if !u.WaitReady(wait) {
		switch t := u.(type) {
		case *Tor:
			_, p, msg := t.Status()
			if msg != "" {
				return nil, errors.New(msg)
			}
			return nil, fmt.Errorf("ещё подключается (%d%%)", p)
		case *Warp:
			if _, msg := t.Status(); msg != "" {
				return nil, errors.New(msg)
			}
		}
		return nil, errors.New("ещё подключается")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	return u.Dial(ctx, host, port)
}

// heavyDial перебирает запасные пути по порядку.
func (e *Engine) heavyDial(host string, port int, ups []Upstream) (net.Conn, Upstream, error) {
	var errs []string
	for _, u := range ups {
		c, err := e.upDial(u, host, port)
		if err == nil {
			return c, u, nil
		}
		errs = append(errs, fmt.Sprintf("через %s: %v", upLabel(u.Name()), err))
	}
	if len(errs) == 0 {
		return nil, nil, errors.New("запасной путь не настроен")
	}
	return nil, nil, errors.New(strings.Join(errs, "; "))
}

func upLabel(name string) string {
	if name == StratWarp {
		return "WARP"
	}
	if name == StratDev {
		return "компьютер разработчика"
	}
	return "Tor"
}

func (e *Engine) handle(c net.Conn) {
	defer c.Close()
	if e.Share != nil {
		c = &countConn{Conn: c} // раздача: считаем трафик пользователя
	}
	e.conns.Add(1)
	defer e.conns.Add(-1)
	e.total.Add(1)
	_ = c.SetDeadline(time.Now().Add(15 * time.Second)) // только на чтение запроса
	br := bufio.NewReaderSize(c, 32*1024)
	b, err := br.Peek(1)
	if err != nil {
		return
	}
	if b[0] == 0x05 {
		e.handleSOCKS(c, br)
		return
	}
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	// Подключение через Tor может занять больше 15 секунд — снимаем ограничение.
	_ = c.SetDeadline(time.Time{})
	if req.Method == http.MethodConnect {
		host, port, err := splitHostPort(req.Host, "443")
		if err != nil {
			_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\n\r\n")
			return
		}
		up, via, err := e.connect(host, port)
		if err != nil {
			badGateway(c, host, err)
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		e.relay(c, br, host, port, nil, up, via)
		return
	}
	// Обычный HTTP через прокси: переписываем запрос в обычную форму (origin-form).
	if req.URL.Host == "" {
		_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return
	}
	host, port, err := splitHostPort(req.URL.Host, "80")
	if err != nil {
		return
	}
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authorization")
	req.Close = true
	req.RequestURI = ""
	up, via, err := e.connect(host, port)
	if err != nil {
		badGateway(c, host, err)
		return
	}
	if req.Body != nil && req.Body != http.NoBody {
		// Запрос с телом (загрузка файла): отправляем потоком, без проверок ответа.
		defer up.Close()
		if err := req.Write(up); err != nil {
			return
		}
		_, _ = io.Copy(c, up)
		return
	}
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		up.Close()
		return
	}
	e.relay(c, br, host, port, buf.Bytes(), up, via)
}

// connect устанавливает первое соединение: напрямую или через запасной путь.
// via — имя пути (StratTor/StratWarp) или "" для прямого соединения.
func (e *Engine) connect(host string, port int) (net.Conn, string, error) {
	if e.Ads.Blocked(host) {
		return nil, "", errAdBlocked
	}
	u, err := e.viaFirst(host)
	if err != nil {
		e.markBlocked(host, err.Error())
		return nil, "", err
	}
	if u != nil {
		up, err := e.upDial(u, host, port)
		if err != nil {
			err = fmt.Errorf("через %s: %v", upLabel(u.Name()), err)
			e.markBlocked(host, err.Error())
			return nil, u.Name(), err
		}
		return up, u.Name(), nil
	}
	up, err := e.dial(context.Background(), host, port)
	if err == nil {
		return up, "", nil
	}
	// Напрямую не подключиться (блокировка по IP или подмена DNS) — пробуем запасные пути
	// (кроме местных сайтов: им нужен настоящий IP).
	ups := e.upstreams()
	if e.Local.HomeIPOnly(host) { // YouTube в России: запасной путь — только WARP (российский IP)
		ups = nil
		if e.warpOn() {
			ups = []Upstream{e.Warp}
		}
	}
	if len(ups) > 0 && !isLocalAddr(host) && !e.Local.Direct(host) {
		e.logf("%s: напрямую недоступен (%s), пробую %s", host, shortErr(err), upLabel(ups[0].Name()))
		up, u, herr := e.heavyDial(host, port, ups)
		if herr == nil {
			e.markOK(host, u.Name(), true)
			return up, u.Name(), nil
		}
		err = fmt.Errorf("%v; %v", err, herr)
	}
	e.markBlocked(host, err.Error())
	return nil, "", err
}

func badGateway(c net.Conn, host string, err error) {
	if errors.Is(err, errAdBlocked) { // реклама: пустой ответ, без страницы ошибки
		_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	msg := fmt.Sprintf("Обход: не удалось подключиться к %s — %v", host, err)
	fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(msg), msg)
}

func splitHostPort(hp, defPort string) (string, int, error) {
	h, p, err := net.SplitHostPort(hp)
	if err != nil {
		h, p = strings.Trim(hp, "[]"), defPort
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 || h == "" {
		return "", 0, errors.New("bad address")
	}
	return strings.ToLower(h), port, nil
}

// readSocksAddr читает адрес SOCKS5 (ATYP + адрес + порт).
func readSocksAddr(br io.Reader, atyp byte) (string, int, error) {
	var host string
	switch atyp {
	case 1:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(br, ip); err != nil {
			return "", 0, err
		}
		host = net.IP(ip).String()
	case 4:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(br, ip); err != nil {
			return "", 0, err
		}
		host = net.IP(ip).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return "", 0, err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(br, name); err != nil {
			return "", 0, err
		}
		host = strings.ToLower(string(name))
	default:
		return "", 0, errors.New("неизвестный тип адреса")
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(pb)), nil
}

func (e *Engine) handleSOCKS(c net.Conn, br *bufio.Reader) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if e.Share != nil {
		// Раздача: только с логином (сведения о пользователе), иначе — отказ.
		if !strings.ContainsRune(string(methods), 2) {
			_, _ = c.Write([]byte{5, 0xFF})
			return
		}
		_, _ = c.Write([]byte{5, 2})
		readField := func() (string, bool) {
			l := make([]byte, 1)
			if _, err := io.ReadFull(br, l); err != nil {
				return "", false
			}
			v := make([]byte, l[0])
			_, err := io.ReadFull(br, v)
			return string(v), err == nil
		}
		ver := make([]byte, 1)
		if _, err := io.ReadFull(br, ver); err != nil {
			return
		}
		user, ok1 := readField()
		pass, ok2 := readField()
		var cl *ShareClient
		if ok1 && ok2 && e.Share.Check != nil {
			cl = e.Share.Check(user, pass)
		}
		if cl == nil {
			_, _ = c.Write([]byte{1, 1})
			return
		}
		_, _ = c.Write([]byte{1, 0})
		if cc, ok := c.(*countConn); ok {
			cc.owner.Store(cl)
		}
		cl.Active.Add(1)
		defer cl.Active.Add(-1)
	} else {
		_, _ = c.Write([]byte{5, 0}) // без пароля
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}
	host, port, err := readSocksAddr(br, req[3])
	if err != nil {
		_, _ = c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	_ = c.SetDeadline(time.Time{})
	switch req[1] {
	case 1: // CONNECT
		host = e.hostFor(host)                     // приложение подключается по адресу из нашего DNS — узнаём имя сайта
		if e.Share != nil && host == devPingHost { // проверка связи от приложения пользователя
			_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
	case 3: // UDP ASSOCIATE — голосовые звонки, игры, DNS и т. п.
		e.socksUDP(c, br)
		return
	default:
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	up, via, err := e.connect(host, port)
	if err != nil {
		code := byte(5) // connection refused
		if errors.Is(err, errAdBlocked) {
			code = 2 // запрещено правилами
		} else if errors.Is(err, errConnect) {
			code = 4 // host unreachable
		}
		_, _ = c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	e.relay(c, br, host, port, nil, up, via)
}

// readFirst читает первые данные клиента (для TLS — целиком первую запись ClientHello).
func readFirst(c net.Conn, br *bufio.Reader) []byte {
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 16*1024)
	for len(buf) < 17*1024 {
		n, err := br.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
		if len(buf) >= 5 && buf[0] == 0x16 {
			if need := 5 + int(binary.BigEndian.Uint16(buf[3:5])); len(buf) >= need {
				break
			}
			continue
		}
		break
	}
	return buf
}

// checkable — можно ли по ответу сервера понять, сработал ли обход: TLS ClientHello
// или короткий HTTP-запрос без тела. Остальное (MTProto Telegram, загрузки файлов,
// игры, голосовые сервисы) передаётся как есть — сервер может молчать, пока не получит
// всё сообщение, и «ожидание ответа» ломало бы такие соединения.
func checkable(first []byte) bool {
	if len(first) == 0 {
		return false
	}
	if first[0] == 0x16 {
		return len(first) >= 6 && first[5] == 0x01 // TLS Handshake: ClientHello
	}
	for _, m := range []string{"GET ", "HEAD ", "OPTIONS "} {
		if bytes.HasPrefix(first, []byte(m)) {
			end := bytes.Index(first, []byte("\r\n\r\n"))
			return end >= 0 && end+4 == len(first)
		}
	}
	return false
}

func (e *Engine) strategiesFor(host string) []string {
	mode, _ := e.Mode.Load().(string)
	if mode != "auto" && validStrategy(mode) && !isUpstreamStrat(mode) {
		return []string{mode}
	}
	e.mu.Lock()
	first := e.learned[host]
	e.mu.Unlock()
	if isUpstreamStrat(first) {
		first = "" // запасной путь сейчас не используется — снова пробуем обход DPI
	}
	base := AutoOrder
	if len(e.upstreams()) > 0 {
		// Есть запасной путь — не тратим время на все методы.
		base = []string{StratTLSRec, StratTLSRecSplit, StratTLSRecDisord, StratNone}
	}
	order := make([]string, 0, len(base)+1)
	if first != "" {
		order = append(order, first)
	}
	for _, s := range base {
		if s != first {
			order = append(order, s)
		}
	}
	return order
}

func isUpstreamStrat(s string) bool { return s == StratTor || s == StratWarp || s == StratDev }

var errConnect = errors.New("не удаётся установить TCP-соединение — вероятно, блокировка по IP или сайт недоступен")

// dial подключается напрямую к первому доступному адресу домена.
func (e *Engine) dial(ctx context.Context, host string, port int) (net.Conn, error) {
	ips, err := e.Resolver.Lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) > 2 {
		ips = ips[:2]
	}
	for _, ip := range ips {
		if ip.IsLoopback() && port == e.selfPt {
			return nil, errors.New("петля прокси")
		}
		c, err := (&net.Dialer{Timeout: e.DialTimeout}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err == nil {
			return c, nil
		}
	}
	return nil, errConnect
}

// relay передаёт данные. pre — уже открытое соединение для первой попытки,
// via — через какой запасной путь оно открыто ("" — напрямую).
func (e *Engine) relay(client net.Conn, br *bufio.Reader, host string, port int, first []byte, pre net.Conn, via string) {
	_ = client.SetDeadline(time.Time{})
	if first == nil {
		first = readFirst(client, br)
	}
	// Через WARP/Tor, протокол, где первым говорит сервер, или поток, по которому нельзя
	// судить о блокировке, — просто соединяем.
	if via != "" || !checkable(first) {
		if len(first) > 0 {
			strat := StratNone
			if via == "" {
				strat = e.learnedDPI(host)
			}
			if err := SendFirst(pre, first, strat); err != nil {
				pre.Close()
				return
			}
		}
		pipe(client, br, pre, nil)
		return
	}

	isTLS := first[0] == 0x16
	var lastErr error
	for i, strat := range e.strategiesFor(host) {
		up, err := pre, error(nil)
		pre = nil
		if up == nil {
			up, err = e.dial(context.Background(), host, port)
		}
		if err != nil {
			lastErr = err
			break
		}
		if err := SendFirst(up, first, strat); err != nil {
			up.Close()
			lastErr = err
			continue
		}
		_ = up.SetReadDeadline(time.Now().Add(e.Timeout))
		resp := make([]byte, 32*1024)
		n, err := up.Read(resp)
		_ = up.SetReadDeadline(time.Time{})
		ok := n > 0 && !(isTLS && resp[0] == 0x15 && strat != StratNone)
		if !ok {
			up.Close()
			if err == nil {
				err = errors.New("сервер ответил ошибкой TLS")
			}
			lastErr = err
			continue
		}
		e.markOK(host, strat, i > 0)
		if _, err := client.Write(resp[:n]); err != nil {
			up.Close()
			return
		}
		pipe(client, br, up, nil)
		return
	}
	if pre != nil {
		pre.Close()
	}

	// Обход DPI не помог — последняя попытка через WARP/Tor.
	ups := e.upstreams()
	if e.Local.HomeIPOnly(host) { // YouTube в России: запасной путь — только WARP (российский IP)
		ups = nil
		if e.warpOn() {
			ups = []Upstream{e.Warp}
		}
	}
	if len(ups) > 0 && !isLocalAddr(host) && !e.Local.Direct(host) {
		e.logf("%s: обход DPI не помог (%s), пробую %s", host, shortErr(lastErr), upLabel(ups[0].Name()))
		var errs []string
		for _, u := range ups {
			up, err := e.upDial(u, host, port)
			if err == nil {
				if _, err = up.Write(first); err == nil {
					_ = up.SetReadDeadline(time.Now().Add(30 * time.Second))
					resp := make([]byte, 32*1024)
					n, rerr := up.Read(resp)
					_ = up.SetReadDeadline(time.Time{})
					if n > 0 {
						e.markOK(host, u.Name(), true)
						if _, err := client.Write(resp[:n]); err == nil {
							pipe(client, br, up, nil)
							return
						}
					}
					err = rerr
				}
				up.Close()
			}
			errs = append(errs, fmt.Sprintf("через %s: %v", upLabel(u.Name()), shortErr(err)))
		}
		lastErr = fmt.Errorf("%v; %s", shortErr(lastErr), strings.Join(errs, "; "))
	}
	reason := "все методы не сработали"
	if lastErr != nil {
		reason += ": " + shortErr(lastErr)
	}
	e.markBlocked(host, reason)
}

// learnedDPI — подобранный для сайта метод обхода DPI (для потоков без проверки ответа).
func (e *Engine) learnedDPI(host string) string {
	mode, _ := e.Mode.Load().(string)
	if mode != "auto" && validStrategy(mode) && !isUpstreamStrat(mode) {
		return mode
	}
	e.mu.Lock()
	l := e.learned[host]
	e.mu.Unlock()
	if l == "" || isUpstreamStrat(l) {
		return StratNone
	}
	return l
}

func shortErr(err error) string {
	if err == nil {
		return "нет ответа"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "через Tor") || strings.Contains(s, "через WARP"):
		return s
	case strings.Contains(s, "timeout"):
		return "нет ответа (DPI сбрасывает пакеты)"
	case strings.Contains(s, "reset"):
		return "соединение сброшено (RST от DPI)"
	case errors.Is(err, io.EOF):
		return "соединение закрыто"
	}
	return s
}

func (e *Engine) markOK(host, strat string, retried bool) {
	if strat == StratDev {
		return // путь «через разработчика» не запоминаем: он выбран режимом, а не сайтом
	}
	if strat != StratTLSRec && strat != StratNone && !isUpstreamStrat(strat) {
		e.fixed.Add(1)
	}
	e.mu.Lock()
	prev := e.learned[host]
	_, wasBlocked := e.blocked[host]
	delete(e.blocked, host)
	changed := false
	if (retried || prev != "") && prev != strat {
		e.learned[host] = strat
		changed = true
	}
	e.mu.Unlock()
	if changed {
		e.logf("%s: подобран метод «%s»", host, StratNames[strat])
		if e.onLearn != nil {
			e.onLearn()
		}
	} else if wasBlocked {
		e.logf("%s: снова доступен", host)
	}
}

func (e *Engine) markBlocked(host, reason string) {
	e.mu.Lock()
	prev := e.blocked[host]
	e.blocked[host] = reason
	e.mu.Unlock()
	if prev != reason {
		e.logf("%s: %s", host, reason)
	}
}

// pipe копирует данные в обе стороны до закрытия.
func pipe(client net.Conn, br *bufio.Reader, up net.Conn, _ []byte) {
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(up, br)
		if tc, ok := up.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, up)
		if tc, ok := client.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// TestResult — результат проверки одного метода.
type TestResult struct {
	Strategy string `json:"strategy"`
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Ms       int64  `json:"ms"`
	Info     string `json:"info"`
}

// TestHost пробует каждый метод: настоящий TLS-handshake и HTTP-запрос к сайту.
func (e *Engine) TestHost(host string, insecure bool) ([]TestResult, error) {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	h, port, err := splitHostPort(host, "443")
	if err != nil {
		return nil, errors.New("введите адрес сайта, например youtube.com")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, dnsErr := e.Resolver.Lookup(ctx, h)
	cancel()
	ups := map[string]Upstream{}
	if e.torOn() {
		ups[StratTor] = e.Tor
	}
	if e.warpOn() {
		ups[StratWarp] = e.Warp
	}
	if dnsErr != nil && len(ups) == 0 {
		return nil, dnsErr
	}
	strats := append([]string(nil), AutoOrder...)
	for _, n := range []string{StratWarp, StratTor} {
		if ups[n] != nil {
			strats = append(strats, n)
		}
	}
	res := make([]TestResult, len(strats))
	var wg sync.WaitGroup
	for i, strat := range strats {
		wg.Add(1)
		go func(i int, strat string) {
			defer wg.Done()
			r := TestResult{Strategy: strat, Name: StratNames[strat]}
			start := time.Now()
			timeout := 9 * time.Second
			u := ups[strat]
			if u != nil {
				timeout = 60 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			var raw net.Conn
			var err error
			if u != nil {
				raw, err = e.upDial(u, h, port)
			} else if dnsErr != nil {
				err = dnsErr
			} else {
				raw, err = e.dial(ctx, h, port)
			}
			if err != nil {
				r.Info = err.Error()
				res[i] = r
				return
			}
			defer raw.Close()
			_ = raw.SetDeadline(time.Now().Add(timeout - time.Second))
			var conn net.Conn = &desyncConn{Conn: raw, strat: strat}
			if u != nil {
				conn = raw
			}
			tc := tls.Client(conn, &tls.Config{ServerName: h, InsecureSkipVerify: insecure, NextProtos: []string{"http/1.1"}})
			if err := tc.HandshakeContext(ctx); err != nil {
				r.Info = shortErr(err)
				res[i] = r
				return
			}
			_, _ = fmt.Fprintf(tc, "HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", h)
			line, err := bufio.NewReader(tc).ReadString('\n')
			if err != nil {
				r.Info = shortErr(err)
				res[i] = r
				return
			}
			r.OK = true
			r.Ms = time.Since(start).Milliseconds()
			r.Info = strings.TrimSpace(line)
			res[i] = r
		}(i, strat)
	}
	wg.Wait()
	return res, nil
}
