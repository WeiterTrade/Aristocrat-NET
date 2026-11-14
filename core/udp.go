package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

// SOCKS5 UDP ASSOCIATE: на Android весь UDP устройства (голосовые звонки, видеосвязь,
// игры, DNS сторонних приложений) приходит из tun2socks сюда. Без этого UDP просто
// пропадал, и голосовые функции мессенджеров и сервисов распознавания речи не работали.
//
// UDP идёт напрямую (обход DPI для него не нужен), в режиме «Всё через WARP» — через WARP.
// QUIC (UDP на порт 443) по умолчанию не пропускаем: приложения сразу переходят на TCP,
// где работает обход блокировок. В режиме «Всё через Tor» UDP не пропускается вовсе —
// Tor его не передаёт, а напрямую он раскрыл бы настоящий IP.

const udpIdle = 3 * time.Minute

// udpHeader разбирает заголовок UDP-пакета SOCKS5: RSV(2) FRAG(1) ATYP адрес порт.
func udpHeader(b []byte) (host string, port int, hdrLen int, ok bool) {
	if len(b) < 4 || b[2] != 0 { // фрагменты не поддерживаем
		return "", 0, 0, false
	}
	switch b[3] {
	case 1:
		if len(b) < 10 {
			return "", 0, 0, false
		}
		return net.IP(b[4:8]).String(), int(binary.BigEndian.Uint16(b[8:10])), 10, true
	case 4:
		if len(b) < 22 {
			return "", 0, 0, false
		}
		return net.IP(b[4:20]).String(), int(binary.BigEndian.Uint16(b[20:22])), 22, true
	case 3:
		if len(b) < 5 {
			return "", 0, 0, false
		}
		l := int(b[4])
		if len(b) < 5+l+2 {
			return "", 0, 0, false
		}
		return string(b[5 : 5+l]), int(binary.BigEndian.Uint16(b[5+l : 7+l])), 7 + l, true
	}
	return "", 0, 0, false
}

// udpPacket добавляет заголовок SOCKS5 к ответу от адреса from.
func udpPacket(from *net.UDPAddr, data []byte) []byte {
	var out []byte
	if ip4 := from.IP.To4(); ip4 != nil {
		out = make([]byte, 10, 10+len(data))
		out[3] = 1
		copy(out[4:8], ip4)
		binary.BigEndian.PutUint16(out[8:10], uint16(from.Port))
	} else {
		out = make([]byte, 22, 22+len(data))
		out[3] = 4
		copy(out[4:20], from.IP.To16())
		binary.BigEndian.PutUint16(out[20:22], uint16(from.Port))
	}
	return append(out, data...)
}

func (e *Engine) socksUDP(c net.Conn, br *bufio.Reader) {
	fail := func() { _, _ = c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}) }
	lc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		fail()
		return
	}
	defer lc.Close()

	route := e.route()
	var out net.PacketConn
	switch {
	case route == RouteTor:
		out = nil // UDP не пропускаем (кроме местных адресов — см. direct ниже)
	case route == RouteWarp:
		if e.warpOn() && e.Warp.WaitReady(15*time.Second) {
			out, err = e.Warp.ListenUDP()
		} else {
			out = nil
		}
	default:
		out, err = net.ListenUDP("udp", nil)
	}
	if err != nil {
		fail()
		return
	}
	if out != nil {
		defer out.Close()
	}

	la := lc.LocalAddr().(*net.UDPAddr)
	if _, err := c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(la.Port >> 8), byte(la.Port)}); err != nil {
		return
	}

	// Отдельный прямой сокет — для российских и казахстанских адресов в режимах Tor и WARP.
	var direct net.PacketConn
	if route == RouteTor || route == RouteWarp {
		if d, err := net.ListenUDP("udp", nil); err == nil {
			direct = d
			defer d.Close()
		}
	}

	var (
		mu     sync.Mutex
		client *net.UDPAddr
		cache  = map[string]net.IP{}
		last   = time.Now()
	)
	touch := func() { mu.Lock(); last = time.Now(); mu.Unlock() }
	resolve := func(host string) net.IP {
		if ip := net.ParseIP(host); ip != nil {
			return ip
		}
		mu.Lock()
		ip, ok := cache[host]
		mu.Unlock()
		if ok {
			return ip
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := e.Resolver.Lookup(ctx, host)
		cancel()
		if err != nil || len(ips) == 0 {
			return nil
		}
		mu.Lock()
		cache[host] = ips[0]
		mu.Unlock()
		return ips[0]
	}

	// Клиент → интернет.
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, from, err := lc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !from.IP.IsLoopback() {
				continue
			}
			mu.Lock()
			client = from
			mu.Unlock()
			host, port, hl, ok := udpHeader(buf[:n])
			if !ok || port == 0 || (e.BlockQUIC && port == 443) {
				continue
			}
			ip := resolve(host)
			if ip == nil || (ip.IsLoopback() && port == e.selfPt) {
				continue
			}
			dst := out
			if direct != nil && e.Local.DirectIP(ip) {
				dst = direct
			}
			if dst == nil {
				continue
			}
			touch()
			_, _ = dst.WriteTo(buf[hl:n], &net.UDPAddr{IP: ip, Port: port})
		}
	}()

	// Интернет → клиент.
	back := func(pc net.PacketConn) {
		buf := make([]byte, 64*1024)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			ua, ok := from.(*net.UDPAddr)
			if !ok {
				continue
			}
			mu.Lock()
			dst := client
			mu.Unlock()
			if dst == nil {
				continue
			}
			touch()
			_, _ = lc.WriteToUDP(udpPacket(ua, buf[:n]), dst)
		}
	}
	if out != nil {
		go back(out)
	}
	if direct != nil {
		go back(direct)
	}

	// Ассоциация живёт, пока открыто управляющее TCP-соединение (и не простаивает слишком долго).
	closed := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, br)
		close(closed)
	}()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-closed:
			return
		case <-t.C:
			mu.Lock()
			idle := time.Since(last) > udpIdle
			mu.Unlock()
			if idle {
				return
			}
		}
	}
}

// dialTLSBypass — TLS-соединение к служебному серверу (API WARP) с обходом DPI;
// если напрямую не выходит — через Tor (если он подключён).
func (e *Engine) dialTLSBypass(ctx context.Context, host string, port int) (net.Conn, error) {
	cfg := &tls.Config{ServerName: host, NextProtos: []string{"http/1.1"}}
	var lastErr error
	for _, strat := range []string{StratTLSRec, StratTLSRecSplit, StratNone} {
		raw, err := e.dial(ctx, host, port)
		if err != nil {
			lastErr = err
			break
		}
		tc := tls.Client(&desyncConn{Conn: raw, strat: strat}, cfg)
		hctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		err = tc.HandshakeContext(hctx)
		cancel()
		if err == nil {
			return tc, nil
		}
		raw.Close()
		lastErr = err
	}
	if e.Tor != nil && e.Tor.WaitReady(0) {
		if c, err := e.Tor.Dial(ctx, host, port); err == nil {
			tc := tls.Client(c, cfg)
			if err := tc.HandshakeContext(ctx); err == nil {
				return tc, nil
			}
			c.Close()
		}
	}
	return nil, lastErr
}
