//go:build dev

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDevPassword(t *testing.T) {
	// RFC 7914 (PBKDF2-HMAC-SHA256, 1 итерация, первые 32 байта): "passwd"/"salt".
	got := hex.EncodeToString(pbkdf2SHA256([]byte("passwd"), []byte("salt"), 1))
	if got != "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc" {
		t.Fatalf("pbkdf2: %s", got)
	}
	old := devPassHash
	defer func() { devPassHash = old }()
	devPassHash = hex.EncodeToString(pbkdf2SHA256([]byte("testpass123"), []byte(devPassSalt), devPassIter))
	if err := checkDevPassword(" test pass 123 "); err != nil {
		t.Fatalf("верный пароль с пробелами: %v", err)
	}
	if checkDevPassword("wrong") == nil {
		t.Fatal("неверный пароль принят")
	}
}

func TestDevKeyRoundTrip(t *testing.T) {
	a := &App{dir: t.TempDir()}
	d := newDevServer(a)
	_, fp, tok, err := d.directIdentity()
	if err != nil {
		t.Fatal(err)
	}
	key, err := d.ExportKey()
	if err != nil {
		t.Fatal(err)
	}
	// восстановление на «другом компьютере»
	b := &App{dir: t.TempDir()}
	d2 := newDevServer(b)
	if err := d2.ImportKey("мусор\n" + key + "\n"); err != nil {
		t.Fatal(err)
	}
	_, fp2, tok2, err := d2.directIdentity()
	if err != nil || fp2 != fp || tok2 != tok {
		t.Fatalf("после восстановления другой ключ: %v", err)
	}
	if d2.ImportKey("не ключ") == nil {
		t.Fatal("мусор принят как ключ")
	}
	// журнал
	if d.check("0123456789abcdef", devInfo("Ноутбук", "5.6.7.8", "RU", "Казань")) == nil {
		t.Fatal("клиент не пущен")
	}
	if d.check("bad", "") != nil {
		t.Fatal("неверный логин пущен")
	}
	if j := d.JournalText(); !strings.Contains(j, "Ноутбук · Казань, Россия · IP 5.6.7.8") {
		t.Fatalf("журнал: %s", j)
	}
}

func TestDirectShareEndToEnd(t *testing.T) {
	dir := t.TempDir()
	a := &App{dir: dir}
	a.s = defaultSettings()
	a.s.Route = RouteDPI // без WARP и Tor в тесте
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	a.s.DevDirectPort = ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	a.res = NewResolver("cloudflare", t.Logf)
	a.eng = NewEngine(a.res, t.Logf)
	a.tor = NewTor(t.Logf)
	a.warp = NewWarp(dir, t.Logf)
	a.ads = NewAdBlock(dir, nil)
	d := newDevServer(a)
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	defer d.Stop()
	_, fp, tok, err := d.directIdentity()
	if err != nil {
		t.Fatal(err)
	}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "moscow-ok") }))
	defer site.Close()

	old := devDirectCode
	defer func() { devDirectCode = old }()
	devDirectCode = fmt.Sprintf("d1:127.0.0.1:%d:%s:%s", a.s.DevDirectPort, fp, tok)
	if !directAvailable() {
		t.Fatalf("код не распознан: %s", devDirectCode)
	}
	dl := NewDirectLink(t.TempDir(), t.Logf)
	dl.Info = func() string { return devInfo("Телефон", "9.9.9.9", "RU", "Анадырь") }
	if st := dl.probe(); st != "ready" {
		t.Fatalf("проверка связи: %s (%s)", st, dl.lastErr)
	}
	_, p, _ := net.SplitHostPort(strings.TrimPrefix(site.URL, "http://"))
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
	if !strings.Contains(string(b), "moscow-ok") {
		t.Fatalf("ответ: %q", b)
	}
	if j := d.JournalText(); !strings.Contains(j, "Телефон · Анадырь, Россия") {
		t.Fatalf("журнал: %s", j)
	}
	// чужой ключ доступа — не пускает
	devDirectCode = fmt.Sprintf("d1:127.0.0.1:%d:%s:%s", a.s.DevDirectPort, fp, strings.Repeat("0", 32))
	bad := NewDirectLink(t.TempDir(), t.Logf)
	if st := bad.probe(); st == "ready" {
		t.Fatal("пустил с чужим ключом")
	}
	// чужой сертификат — клиент не подключается
	devDirectCode = fmt.Sprintf("d1:127.0.0.1:%d:%s:%s", a.s.DevDirectPort, strings.Repeat("a", 64), tok)
	if st := NewDirectLink(t.TempDir(), t.Logf).probe(); st == "ready" {
		t.Fatal("подключился к серверу с чужим сертификатом")
	}
}
