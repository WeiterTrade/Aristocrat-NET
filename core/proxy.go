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
	Resolver *Resolver
	Mode     atomic.Value // "auto" или конкретный метод обхода DPI
	Route    atomic.Value // RouteAuto | RouteDPI | RouteTor
	Tor      *Tor
	Timeout  time.Duration // ожидание ответа сервера на каждый метод
	TorWait  time.Duration // сколько ждать подключения Tor при фолбэке

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
	e := &Engine{Resolver: r, Timeout: 3 * time.Second, TorWait: 40 * time.Second, DialTimeout: 4 * time.Second,
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
	RouteAuto = "auto" // обход DPI, при неудаче — Tor
	RouteDPI  = "dpi"  // только обход DPI
	RouteTor  = "tor"  // всё через Tor
)

var RouteNames = map[string]string{
	RouteAuto: "Авто: обход DPI, при блокировке — Tor",
	RouteDPI:  "Только обход DPI",
	RouteTor:  "Всё через Tor",
}

func (e *Engine) route() string {
	r, _ := e.Route.Load().(string)
	if r == "" {
		return RouteAuto
	}
	return r
}

func (e *Engine) torAvailable() bool { return e.Tor != nil && e.Tor.Enabled() }

// viaTorFirst — сразу через Tor, не пытаясь напрямую.
func (e *Engine) viaTorFirst(host string) bool {
	if strings.HasSuffix(host, ".onion") {
		return true
	}
	if isLocalAddr(host) {
		return false
	}
	switch e.route() {
	case RouteTor:
		return true
	case RouteDPI:
		return false
	}
	e.mu.Lock()
	l := e.learned[host]
	e.mu.Unlock()
	return l == StratTor && e.torAvailable()
}

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}
var benchmark = &net.IPNet{IP: net.IPv4(198, 18, 0, 0), Mask: net.CIDRMask(15, 32)}

// isLocalAddr — локальные и служебные адреса: в Tor их отправлять бессмысленно.
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

// torFallbackAllowed — можно ли уйти в Tor, если напрямую не вышло.
func (e *Engine) torFallbackAllowed() bool {
	return e.route() != RouteDPI && e.torAvailable()
}

func (e *Engine) torDial(host string, port int) (net.Conn, error) {
	if e.Tor == nil {
		return nil, errors.New("Tor не настроен")
	}
	if !e.Tor.WaitReady(e.TorWait) {
		_, p, _ := e.Tor.Status()
		return nil, fmt.Errorf("Tor ещё подключается (%d%%)", p)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return e.Tor.Dial(ctx, host, port)
}

func (e *Engine) handle(c net.Conn) {
	defer c.Close()
	e.conns.Add(1)
	defer e.conns.Add(-1)
	e.total.Add(1)
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
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
	if req.Method == http.MethodConnect {
		host, port, err := splitHostPort(req.Host, "443")
		if err != nil {
			_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\n\r\n")
			return
		}
		up, viaTor, err := e.connect(host, port)
		if err != nil {
			badGateway(c, host, err)
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		e.relay(c, br, host, port, nil, up, viaTor)
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
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		return
	}
	up, viaTor, err := e.connect(host, port)
	if err != nil {
		badGateway(c, host, err)
		return
	}
	e.relay(c, br, host, port, buf.Bytes(), up, viaTor)
}

// connect устанавливает первое соединение: напрямую или через Tor.
func (e *Engine) connect(host string, port int) (net.Conn, bool, error) {
	if e.viaTorFirst(host) {
		up, err := e.torDial(host, port)
		if err != nil {
			e.markBlocked(host, err.Error())
			return nil, true, err
		}
		return up, true, nil
	}
	up, err := e.dial(context.Background(), host, port)
	if err == nil {
		return up, false, nil
	}
	// Напрямую не подключиться (блокировка по IP или подмена DNS) — пробуем Tor.
	if e.torFallbackAllowed() && !isLocalAddr(host) {
		e.logf("%s: напрямую недоступен (%s), пробую Tor", host, shortErr(err))
		up, terr := e.torDial(host, port)
		if terr == nil {
			e.markOK(host, StratTor, true)
			return up, true, nil
		}
		err = fmt.Errorf("%v; через Tor: %v", err, terr)
	}
	e.markBlocked(host, err.Error())
	return nil, false, err
}

func badGateway(c net.Conn, host string, err error) {
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

func (e *Engine) handleSOCKS(c net.Conn, br *bufio.Reader) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	if _, err := io.ReadFull(br, make([]byte, hdr[1])); err != nil {
		return
	}
	_, _ = c.Write([]byte{5, 0}) // без пароля
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil || req[1] != 1 {
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0}) // поддерживается только CONNECT
		return
	}
	var host string
	switch req[3] {
	case 1:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 4:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(br, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 3:
		l, err := br.ReadByte()
		if err != nil {
			return
		}
		name := make([]byte, l)
		if _, err := io.ReadFull(br, name); err != nil {
			return
		}
		host = strings.ToLower(string(name))
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(pb))
	up, viaTor, err := e.connect(host, port)
	if err != nil {
		code := byte(5) // connection refused
		if errors.Is(err, errConnect) {
			code = 4 // host unreachable
		}
		_, _ = c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	e.relay(c, br, host, port, nil, up, viaTor)
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

func (e *Engine) strategiesFor(host string) []string {
	mode, _ := e.Mode.Load().(string)
	if mode != "auto" && validStrategy(mode) && mode != StratTor {
		return []string{mode}
	}
	e.mu.Lock()
	first := e.learned[host]
	e.mu.Unlock()
	if first == StratTor {
		first = "" // Tor выключили — снова пробуем обход DPI
	}
	base := AutoOrder
	if e.torFallbackAllowed() {
		// Есть запасной путь через Tor — не тратим время на все методы.
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

func (e *Engine) tunnel(client net.Conn, br *bufio.Reader, host string, port int, first []byte) {
	up, viaTor, err := e.connect(host, port)
	if err != nil {
		return
	}
	e.relay(client, br, host, port, first, up, viaTor)
}

// relay передаёт данные. pre — уже открытое соединение для первой попытки.
func (e *Engine) relay(client net.Conn, br *bufio.Reader, host string, port int, first []byte, pre net.Conn, viaTor bool) {
	_ = client.SetDeadline(time.Time{})
	if first == nil {
		first = readFirst(client, br)
	}
	// Через Tor или протокол, где первым говорит сервер, — просто соединяем.
	if viaTor || len(first) == 0 {
		if len(first) > 0 {
			if _, err := pre.Write(first); err != nil {
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

	// Обход DPI не помог — последняя попытка через Tor.
	if e.torFallbackAllowed() && !isLocalAddr(host) {
		e.logf("%s: обход DPI не помог (%s), пробую Tor", host, shortErr(lastErr))
		up, err := e.torDial(host, port)
		if err == nil {
			if _, err = up.Write(first); err == nil {
				_ = up.SetReadDeadline(time.Now().Add(30 * time.Second))
				resp := make([]byte, 32*1024)
				n, rerr := up.Read(resp)
				_ = up.SetReadDeadline(time.Time{})
				if n > 0 {
					e.markOK(host, StratTor, true)
					if _, err := client.Write(resp[:n]); err == nil {
						pipe(client, br, up, nil)
						return
					}
				}
				err = rerr
			}
			up.Close()
		}
		lastErr = fmt.Errorf("%v; через Tor: %v", shortErr(lastErr), err)
	}
	reason := "все методы не сработали"
	if lastErr != nil {
		reason += ": " + shortErr(lastErr)
	}
	e.markBlocked(host, reason)
}

func shortErr(err error) string {
	if err == nil {
		return "нет ответа"
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "; через Tor"):
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
	if strat != StratTLSRec && strat != StratNone {
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
		if tc, ok := up.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, up)
		if tc, ok := client.(*net.TCPConn); ok {
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
	if dnsErr != nil && !e.torAvailable() {
		return nil, dnsErr
	}
	strats := append([]string(nil), AutoOrder...)
	if e.torAvailable() {
		strats = append(strats, StratTor)
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
			if strat == StratTor {
				timeout = 60 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			var raw net.Conn
			var err error
			if strat == StratTor {
				raw, err = e.torDial(h, port)
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
			if strat == StratTor {
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
