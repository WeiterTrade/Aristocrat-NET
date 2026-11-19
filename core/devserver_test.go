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

// delayProxy — TCP-посредник с задержкой в каждую сторону (имитация дальнего сервера).
func delayProxy(t *testing.T, target string, oneWay time.Duration) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	pump := func(dst, src net.Conn) {
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				time.Sleep(oneWay)
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		dst.Close()
		src.Close()
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			go pump(s, c)
			go pump(c, s)
		}
	}()
	return ln.Addr().String()
}

func TestDirectLinkLatencyAndRestart(t *testing.T) {
	dir := t.TempDir()
	a := &App{dir: dir}
	a.s = defaultSettings()
	a.s.Route = RouteDPI
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
	_, fp, tok, _ := d.directIdentity()
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer site.Close()
	_, p, _ := net.SplitHostPort(strings.TrimPrefix(site.URL, "http://"))
	pn, _ := strconv.Atoi(p)

	const oneWay = 40 * time.Millisecond // отклик 80 мс
	px := delayProxy(t, net.JoinHostPort("127.0.0.1", strconv.Itoa(a.s.DevDirectPort)), oneWay)
	_, pxPort, _ := net.SplitHostPort(px)
	old := devDirectCode
	defer func() { devDirectCode = old }()
	devDirectCode = fmt.Sprintf("d1:127.0.0.1:%s:%s:%s", pxPort, fp, tok)
	dl := NewDirectLink(t.TempDir(), t.Logf)
	get := func() time.Duration {
		t0 := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := dl.Dial(ctx, "127.0.0.1", pn)
		if err != nil {
			t.Fatal(err)
		}
		el := time.Since(t0)
		io.WriteString(c, "GET / HTTP/1.0\r\nHost: x\r\n\r\n")
		b, _ := io.ReadAll(c)
		c.Close()
		if !strings.Contains(string(b), "ok") {
			t.Fatalf("ответ: %q", b)
		}
		return el
	}
	cold := get()
	time.Sleep(time.Second) // запас наполнится
	warm := get()
	t.Logf("подключение: холодное %v, из запаса %v (отклик 80 мс)", cold, warm)
	if cold > 6*2*oneWay {
		t.Fatalf("холодное подключение слишком долгое: %v (больше 6 обменов)", cold)
	}
	if warm > 2*2*oneWay {
		t.Fatalf("подключение из запаса слишком долгое: %v", warm)
	}
	// Сервер перезапущен — заготовленные соединения мертвы, подключение всё равно проходит.
	time.Sleep(500 * time.Millisecond)
	d.Stop()
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	get()
}

// Пользователь → сервер раздачи → компьютер-выход → сайт.
func TestExitThroughDevComputer(t *testing.T) {
	oldHash := devPassHash
	defer func() { devPassHash = oldHash }()
	devPassHash = hex.EncodeToString(pbkdf2SHA256([]byte("testpass123"), []byte(devPassSalt), 1))

	mk := func() *App {
		dir := t.TempDir()
		a := &App{dir: dir}
		a.s = defaultSettings()
		a.s.Route = RouteDPI
		a.res = NewResolver("cloudflare", t.Logf)
		a.eng = NewEngine(a.res, t.Logf)
		a.tor = NewTor(t.Logf)
		a.warp = NewWarp(dir, t.Logf)
		a.ads = NewAdBlock(dir, nil)
		return a
	}
	srvApp := mk()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srvApp.s.DevDirectPort = ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	srv := newDevServer(srvApp)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()
	_, fp, tok, _ := srv.directIdentity()
	old := devDirectCode
	defer func() { devDirectCode = old }()
	devDirectCode = fmt.Sprintf("d1:127.0.0.1:%d:%s:%s", srvApp.s.DevDirectPort, fp, tok)

	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "kz-ok") }))
	defer site.Close()
	_, p, _ := net.SplitHostPort(strings.TrimPrefix(site.URL, "http://"))
	pn, _ := strconv.Atoi(p)

	// компьютер-выход
	kz := newDevServer(mk())
	if err := kz.StartExit(); err != nil {
		t.Fatal(err)
	}
	defer kz.StopExit()
	for i := 0; i < 100 && !srv.exitRecent(); i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if !srv.exitRecent() {
		t.Fatalf("выход не подключился: %s", kz.ExitStatus())
	}
	if st := srv.Status(); !strings.Contains(st, "выход через компьютер") {
		t.Fatalf("состояние сервера: %s", st)
	}
	dl := NewDirectLink(t.TempDir(), t.Logf)
	get := func() string {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := dl.Dial(ctx, "127.0.0.1", pn)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(c, "GET / HTTP/1.0\r\nHost: x\r\n\r\n")
		b, _ := io.ReadAll(c)
		c.Close()
		return string(b)
	}
	before := kz.agent.eng.total.Load()
	for i := 0; i < 20; i++ {
		if b := get(); !strings.Contains(b, "kz-ok") {
			t.Fatalf("ответ: %q", b)
		}
	}
	if n := kz.agent.eng.total.Load() - before; n < 20 {
		t.Fatalf("через выход прошло %d из 20 подключений", n)
	}
	// выход выключен — сервер открывает сайты сам
	kz.StopExit()
	srv.exits.mu.Lock()
	srv.exits.seen = time.Time{}
	srv.exits.mu.Unlock()
	if b := get(); !strings.Contains(b, "kz-ok") {
		t.Fatalf("без выхода: %q", b)
	}
	// чужой пароль выхода — не пускают
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := dl.dialTo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	user, pass := exitUserPrefix+tok, strings.Repeat("0", 64)
	msg := append([]byte{5, 1, 2, 1, byte(len(user))}, user...)
	msg = append(append(msg, byte(len(pass))), pass...)
	c.Write(msg)
	r := make([]byte, 4)
	if _, err := io.ReadFull(c, r); err != nil || r[3] == 0 {
		t.Fatalf("чужой выход пущен: %v %v", r, err)
	}
}
