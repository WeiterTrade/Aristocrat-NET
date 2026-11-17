package main

import (
	"bufio"
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

// fakeOnionTor — «Tor», который любое подключение (к адресу .onion) отправляет на прокси раздачи.
func fakeOnionTor(t *testing.T, target string) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				h := make([]byte, 2)
				io.ReadFull(r, h)
				io.ReadFull(r, make([]byte, h[1]))
				c.Write([]byte{5, 0})
				req := make([]byte, 4)
				io.ReadFull(r, req)
				if req[3] == 3 {
					l := make([]byte, 1)
					io.ReadFull(r, l)
					io.ReadFull(r, make([]byte, int(l[0])+2))
				}
				up, err := net.Dial("tcp", target)
				if err != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go io.Copy(up, r)
				io.Copy(c, up)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestDevLinkThroughShareProxy(t *testing.T) {
	old := devCode
	devCode = strings.Repeat("a", 56) + ":" + strings.Repeat("B", 52)
	defer func() { devCode = old }()
	if !devAvailable() {
		t.Fatal("код подключения не распознан")
	}

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello-from-site") }))
	defer site.Close()

	// Прокси раздачи с входом по логину.
	var gotUser, gotPass string
	stats := &ShareClient{}
	share := NewEngine(NewResolver("cloudflare", t.Logf), t.Logf)
	share.Route.Store(RouteDPI)
	share.Share = &ShareAuth{Check: func(u, p string) *ShareClient {
		if len(u) != 16 {
			return nil
		}
		gotUser, gotPass = u, p
		return stats
	}}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	if err := share.Start(port); err != nil {
		t.Fatal(err)
	}
	defer share.Stop()

	tor := NewTor(t.Logf)
	tor.UseExternal(fakeOnionTor(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(port))))
	if !tor.WaitReady(8 * time.Second) {
		t.Fatal("фейковый Tor не готов")
	}
	defer tor.Stop()

	dl := NewDevLink(tor, t.TempDir(), t.Logf)
	dl.Info = func() string { return devInfo("Телефон", "1.2.3.4", "RU", "Москва") }
	if st := dl.probe(); st != "ready" {
		t.Fatalf("проверка связи: %s", st)
	}
	u := strings.TrimPrefix(site.URL, "http://")
	_, p, _ := net.SplitHostPort(u)
	pn, _ := strconv.Atoi(p)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := dl.Dial(ctx, "127.0.0.1", pn)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "GET / HTTP/1.0\r\nHost: x\r\n\r\n")
	b, _ := io.ReadAll(c)
	c.Close()
	if !strings.Contains(string(b), "hello-from-site") {
		t.Fatalf("ответ: %q", b)
	}
	if len(gotUser) != 16 || !strings.Contains(gotPass, "Телефон|1.2.3.4|RU|Москва") {
		t.Fatalf("сведения о пользователе: %q %q", gotUser, gotPass)
	}
	time.Sleep(100 * time.Millisecond)
	if stats.Down.Load() == 0 || stats.Up.Load() == 0 {
		t.Fatalf("трафик не посчитан: %d/%d", stats.Down.Load(), stats.Up.Load())
	}

	// Без логина прокси раздачи не пускает.
	raw, _ := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	raw.Write([]byte{5, 1, 0})
	r := make([]byte, 2)
	io.ReadFull(raw, r)
	raw.Close()
	if r[1] != 0xFF {
		t.Fatalf("без логина: %v", r)
	}
}

func TestDevCodeAndAuthFile(t *testing.T) {
	old := devCode
	defer func() { devCode = old }()
	devCode = ""
	if devAvailable() || writeDevClientAuth(t.TempDir()) != "" {
		t.Fatal("без кода режима быть не должно")
	}
	devCode = strings.Repeat("x", 56) + ".onion:" + strings.Repeat("k", 52)
	dir := t.TempDir()
	if writeDevClientAuth(dir) == "" {
		t.Fatal("файл ключа не записан")
	}
	rc, _ := BuildTorrc(TorOptions{Bridges: "none", SocksAddr: torSocksAddr, ClientAuthDir: dir})
	if !strings.Contains(rc, "ClientOnionAuthDir "+dir) {
		t.Fatalf("torrc: %s", rc)
	}
}
