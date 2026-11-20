package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLanPeer(t *testing.T) {
	for addr, want := range map[string]bool{
		"192.168.49.23": true, "10.1.2.3": true, "172.20.0.5": true, "127.0.0.1": true,
		"8.8.8.8": false, "100.70.1.1": false, "95.31.2.3": false,
	} {
		if got := lanPeer(&net.TCPAddr{IP: net.ParseIP(addr), Port: 1}); got != want {
			t.Errorf("%s: %v, нужно %v", addr, got, want)
		}
	}
}

// Раздача без обхода: телевизор (прокси в настройках Wi-Fi) открывает сайт через телефон.
func TestWifiShareProxy(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "phone-ok") }))
	defer site.Close()
	e := NewEngine(NewResolver("cloudflare", t.Logf), t.Logf)
	e.Plain.Store(true)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	e.ServeLAN(ln)
	proxyAddr := ln.Addr().String()

	// обычный HTTP через прокси
	cl := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(mustURL("http://" + proxyAddr))}}
	resp, err := cl.Get(site.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "phone-ok" {
		t.Fatalf("HTTP: %q", b)
	}
	// CONNECT (так ходят все HTTPS-сайты)
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(site.URL, "http://")
	io.WriteString(c, "CONNECT "+host+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
	br := bufio.NewReader(c)
	line, _ := br.ReadString('\n')
	if !strings.Contains(line, "200") {
		t.Fatalf("CONNECT: %q", line)
	}
	for l, _ := br.ReadString('\n'); l != "\r\n" && l != ""; l, _ = br.ReadString('\n') {
	}
	io.WriteString(c, "GET / HTTP/1.0\r\nHost: x\r\n\r\n")
	rest, _ := io.ReadAll(br)
	c.Close()
	if !strings.Contains(string(rest), "phone-ok") {
		t.Fatalf("через CONNECT: %q", rest)
	}
	// страница и автонастройка на самом прокси
	for path, want := range map[string]string{"/": "раздача работает", "/proxy.pac": "PROXY " + proxyAddr} {
		resp, err := http.Get("http://" + proxyAddr + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(b), want) {
			t.Fatalf("%s: %q", path, b)
		}
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// Приём интернета с телефона: UDP (звонки, DNS) второго устройства идёт через прокси телефона.
func TestShareUDPForLanClient(t *testing.T) {
	var lanIP net.IP
	if ifs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range ifs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
				lanIP = n.IP.To4()
				break
			}
		}
	}
	if lanIP == nil {
		t.Skip("нет сетевого адреса, кроме 127.0.0.1")
	}
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFrom(buf)
			if err != nil {
				return
			}
			echo.WriteTo(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	e := NewEngine(NewResolver("cloudflare", t.Logf), t.Logf)
	e.Plain.Store(true)
	ln, err := net.Listen("tcp", net.JoinHostPort(lanIP.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { // как ServeLAN, но без проверки адреса: в тестовой среде он может быть не «домашним»
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go e.handle(c)
		}
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	r := make([]byte, 12)
	if _, err := io.ReadFull(c, r); err != nil || r[1] != 0 || r[3] != 0 {
		t.Fatalf("UDP ASSOCIATE: %v %v", r, err)
	}
	relay := &net.UDPAddr{IP: net.IP(r[6:10]), Port: int(r[10])<<8 | int(r[11])}
	if !relay.IP.Equal(lanIP) {
		t.Fatalf("адрес для UDP %v, нужен адрес телефона %v", relay.IP, lanIP)
	}
	u, err := net.DialUDP("udp", &net.UDPAddr{IP: lanIP}, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	ep := echo.LocalAddr().(*net.UDPAddr)
	pkt := append([]byte{0, 0, 0, 1, 127, 0, 0, 1, byte(ep.Port >> 8), byte(ep.Port)}, "ping"...)
	u.Write(pkt)
	u.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, err := u.Read(buf)
	if err != nil || !strings.HasSuffix(string(buf[:n]), "echo:ping") {
		t.Fatalf("ответ UDP: %q %v", buf[:n], err)
	}
}
