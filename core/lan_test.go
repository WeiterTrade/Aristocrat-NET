package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Приём интернета с телефона: прокси компьютера отправляет всё в прокси телефона,
// служебные соединения программы (DNS, внешний IP) — тоже.
func TestReceiveThroughPhone(t *testing.T) {
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "via-phone") }))
	defer site.Close()

	phone := NewEngine(NewResolver("cloudflare", t.Logf), t.Logf)
	phone.Plain.Store(true)
	pln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pln.Close()
	phone.ServeLAN(pln)
	if !probeShare("127.0.0.1", time.Second) {
		// probeShare стучится на порт 8282 — здесь порт другой, проверяем страницу напрямую
		resp, err := http.Get("http://" + pln.Addr().String() + "/")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(b), "Aristocrat NET") {
			t.Fatalf("страница раздачи: %q", b)
		}
	}

	pc := NewEngine(NewResolver("cloudflare", t.Logf), t.Logf)
	link := &phoneLink{addr: pln.Addr().String()}
	pc.setForced(link)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if err := pc.Start(port); err != nil {
		t.Fatal(err)
	}
	defer pc.Stop()

	before := phone.total.Load()
	cl := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(mustURL("http://127.0.0.1:" + strconv.Itoa(port)))}}
	for i := 0; i < 3; i++ {
		resp, err := cl.Get(site.URL)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != "via-phone" {
			t.Fatalf("ответ: %q", b)
		}
	}
	if n := phone.total.Load() - before; n < 3 {
		t.Fatalf("через телефон прошло %d из 3 запросов", n)
	}

	// служебные соединения программы — тоже через телефон
	recvLink.Store(link)
	defer recvLink.Store(nil)
	before = phone.total.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := netDial(ctx, "tcp", strings.TrimPrefix(site.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if phone.total.Load() == before {
		t.Fatal("служебное соединение прошло мимо телефона")
	}
}

func TestDefaultGatewayParses(t *testing.T) {
	_ = defaultGateway() // не падает; в тестовой среде роутера может не быть
	if len(lanAddrs()) > 0 {
		for _, a := range lanAddrs() {
			if ip := net.ParseIP(a); ip == nil || !ip.IsPrivate() {
				t.Fatalf("не домашний адрес: %s", a)
			}
		}
	}
}

func TestShareStartStop(t *testing.T) {
	dir := t.TempDir()
	a := &App{dir: dir}
	a.s = defaultSettings()
	a.res = NewResolver("cloudflare", t.Logf)
	a.eng = NewEngine(a.res, t.Logf)
	a.tor = NewTor(t.Logf)
	a.warp = NewWarp(dir, t.Logf)
	a.ads = NewAdBlock(dir, nil)
	if err := a.shareStart(false); err != nil {
		t.Skip("порт 8282 занят: ", err)
	}
	if on, bypass := a.shareOn(); !on || bypass {
		t.Fatal("раздача не включилась")
	}
	if !probeShare("127.0.0.1", time.Second) {
		t.Fatal("раздача не отвечает на порту 8282")
	}
	if err := a.recvStart(); err == nil {
		t.Fatal("приём включился одновременно с раздачей")
	}
	a.shareStop()
	if on, _ := a.shareOn(); on || probeShare("127.0.0.1", 500*time.Millisecond) {
		t.Fatal("раздача не выключилась")
	}
}
