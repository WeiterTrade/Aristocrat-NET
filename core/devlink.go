package main

// «Через разработчика»: трафик пользователя выходит в интернет через компьютер разработчика
// (в Казахстане). Компьютер разработчика — скрытый сервис Tor (адрес .onion), поэтому ему
// не нужен белый IP. Адрес и ключ доступа (код подключения) вшиваются в пользовательские
// сборки при сборке на GitHub (файл dev-code.txt → -X main.devCode=…).
//
// Подключение: Tor пользователя (с мостами) → адрес .onion → прокси SOCKS5 на компьютере
// разработчика. В логине SOCKS5 приложение сообщает о себе: номер установки, имя устройства,
// свой IP, страну и город, версию — разработчик видит это в журнале (пользователь
// предупреждается при выборе режима).

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// devCode — код подключения «адрес-onion-без-.onion:ключ-x25519-base32» (задаётся при сборке).
var devCode = ""

const (
	RouteDev = "dev" // всё через компьютер разработчика
	StratDev = "dev"
)

func init() {
	if devAvailable() {
		RouteNames[RouteDev] = "Эдик на Чукотке"
	}
}

// devAvailable — в этой сборке есть код подключения к разработчику.
func devAvailable() bool {
	_, _, ok := parseDevCode(devCode)
	return ok
}

func parseDevCode(code string) (onion, key string, ok bool) {
	code = strings.TrimSpace(code)
	onion, key, ok = strings.Cut(code, ":")
	onion = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(onion)), ".onion")
	key = strings.ToUpper(strings.TrimSpace(key))
	return onion, key, ok && len(onion) == 56 && len(key) == 52
}

// writeDevClientAuth — ключ доступа для Tor пользователя (ClientOnionAuthDir).
// Возвращает папку для torrc ("" — кода нет).
func writeDevClientAuth(dir string) string {
	onion, key, ok := parseDevCode(devCode)
	if !ok {
		return ""
	}
	_ = os.MkdirAll(dir, 0o700)
	line := fmt.Sprintf("%s:descriptor:x25519:%s\n", onion, key)
	if os.WriteFile(filepath.Join(dir, "aristocrat.auth_private"), []byte(line), 0o600) != nil {
		return ""
	}
	return dir
}

// DevLink — путь «через разработчика» (Upstream для движка).
type DevLink struct {
	Tor  *Tor
	Info func() string // сведения о себе для журнала разработчика

	onion string
	id    string // номер установки (постоянный)
	logf  func(string, ...any)

	mu      sync.Mutex
	lastErr string // причина последней неудачи (для журнала)
	state   string // "", "connecting", "ready", "down"
	checked time.Time
	running bool
}

func NewDevLink(t *Tor, dir string, logf func(string, ...any)) *DevLink {
	onion, _, ok := parseDevCode(devCode)
	if !ok {
		return nil
	}
	d := &DevLink{Tor: t, onion: onion + ".onion", logf: logf}
	p := filepath.Join(dir, "install-id")
	if b, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(b))) == 16 {
		d.id = strings.TrimSpace(string(b))
	} else {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		d.id = hex.EncodeToString(b)
		_ = os.MkdirAll(dir, 0o700)
		_ = os.WriteFile(p, []byte(d.id), 0o600)
	}
	return d
}

func (d *DevLink) Name() string { return StratDev }

func (d *DevLink) Enabled() bool { return d != nil && d.Tor != nil && d.Tor.Enabled() }

// State — для интерфейса: "connecting" | "ready" | "down" | "".
func (d *DevLink) State() string {
	if d == nil {
		return ""
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.state
}

// WaitReady — компьютер разработчика сейчас отвечает (проверяется в фоне).
func (d *DevLink) WaitReady(wait time.Duration) bool {
	if d == nil {
		return false
	}
	end := time.Now().Add(wait)
	for {
		if d.State() == "ready" {
			return true
		}
		if time.Now().After(end) {
			return false
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// Watch проверяет связь с разработчиком, пока активен режим (active() == true).
func (d *DevLink) Watch(active func() bool) {
	if d == nil {
		return
	}
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return
	}
	d.running = true
	d.mu.Unlock()
	go func() {
		defer func() { d.mu.Lock(); d.running = false; d.state = ""; d.mu.Unlock() }()
		last := ""
		for active() {
			st := d.probe()
			d.mu.Lock()
			d.state, d.checked = st, time.Now()
			d.mu.Unlock()
			if st != last {
				switch st {
				case "ready":
					d.logf("Разработчик на связи — трафик идёт через его компьютер")
				case "down":
					d.mu.Lock()
					why := d.lastErr
					d.mu.Unlock()
					d.logf("Компьютер разработчика сейчас недоступен (%s) — работает обычный режим", why)
				}
				last = st
			}
			wait := 60 * time.Second
			if st != "ready" {
				wait = 30 * time.Second
			}
			for i := 0; i < int(wait/time.Second) && active(); i++ {
				time.Sleep(time.Second)
			}
		}
	}()
}

func (d *DevLink) probe() string {
	d.mu.Lock()
	first := d.state == ""
	d.mu.Unlock()
	if first {
		d.logf("Подключаюсь к компьютеру разработчика (%s…) — первый раз это занимает до минуты", d.onion[:8])
	}
	if !d.Tor.WaitReady(0) {
		d.mu.Lock()
		if d.state == "" {
			d.state = "connecting"
		}
		d.mu.Unlock()
		if !d.Tor.WaitReady(90 * time.Second) {
			return "connecting"
		}
	}
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		c, err := d.dialSOCKS(ctx, devPingHost, 1)
		cancel()
		if err == nil {
			c.Close()
			return "ready"
		}
		d.mu.Lock()
		d.lastErr = err.Error()
		d.mu.Unlock()
	}
	return "down"
}

const devPingHost = "aristonet.ping"

func (d *DevLink) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	return d.dialSOCKS(ctx, host, port)
}

// dialSOCKS: Tor → адрес разработчика → SOCKS5 с логином (сведения о себе) → CONNECT host:port.
func (d *DevLink) dialSOCKS(ctx context.Context, host string, port int) (net.Conn, error) {
	c, err := d.Tor.Dial(ctx, d.onion, 443)
	if err != nil {
		return nil, fmt.Errorf("разработчик недоступен: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	fail := func(e error) (net.Conn, error) { c.Close(); return nil, e }
	if _, err := c.Write([]byte{5, 1, 2}); err != nil {
		return fail(err)
	}
	r := make([]byte, 2)
	if _, err := io.ReadFull(c, r); err != nil || r[1] != 2 {
		return fail(errors.New("разработчик: неверный ответ"))
	}
	user, pass := d.id, ""
	if d.Info != nil {
		pass = d.Info()
	}
	if len(pass) > 255 {
		pass = pass[:255]
	}
	auth := append([]byte{1, byte(len(user))}, user...)
	auth = append(append(auth, byte(len(pass))), pass...)
	if _, err := c.Write(auth); err != nil {
		return fail(err)
	}
	if _, err := io.ReadFull(c, r); err != nil || r[1] != 0 {
		return fail(errors.New("разработчик не принял подключение"))
	}
	if len(host) > 255 {
		return fail(errors.New("слишком длинное имя"))
	}
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append(append(req, 1), ip.To4()...)
	} else if ip != nil {
		req = append(append(req, 4), ip.To16()...)
	} else {
		req = append(append(req, 3, byte(len(host))), host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		return fail(err)
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return fail(err)
	}
	if hdr[1] != 0 {
		return fail(fmt.Errorf("разработчик: не удалось подключиться к %s (код %d)", host, hdr[1]))
	}
	skip := 0
	switch hdr[3] {
	case 1:
		skip = 4 + 2
	case 4:
		skip = 16 + 2
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return fail(err)
		}
		skip = int(l[0]) + 2
	}
	if _, err := io.ReadFull(c, make([]byte, skip)); err != nil {
		return fail(err)
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// devInfo — «v1|имя устройства|IP|страна|город|версия» (разделитель | в полях заменяется).
func devInfo(device, ip, cc, city string) string {
	clean := func(s string) string {
		s = strings.ReplaceAll(strings.TrimSpace(s), "|", "/")
		if len(s) > 60 {
			s = s[:60]
		}
		return s
	}
	return strings.Join([]string{"v1", clean(device), clean(ip), clean(cc), clean(city), clean(appVersion)}, "|")
}
