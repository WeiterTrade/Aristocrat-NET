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
