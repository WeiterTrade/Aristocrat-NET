package main

// Общая часть маршрута «через разработчика» («Ебаная Чукотка», см. devdirect.go):
// трафик пользователя выходит в интернет через компьютер разработчика с белым IP.
// В логине SOCKS5 приложение сообщает о себе: номер установки, имя устройства,
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

const StratDev = "dev"

// DevLink — путь «через разработчика» (Upstream для движка).
type DevLink struct {
	Info func() string // сведения о себе для журнала разработчика

	id     string // номер установки (постоянный)
	logf   func(string, ...any)
	label  string                                      // для журнала
	prefix string                                      // начало логина (ключ доступа)
	dialTo func(ctx context.Context) (net.Conn, error) // TLS до прокси раздачи

	mu      sync.Mutex
	pool    []warmConn // заранее открытые соединения (TCP+TLS уже готовы)
	lastUse time.Time
	filling bool
	rtt     time.Duration // отклик сервера (последняя проверка)
	lastErr string        // причина последней неудачи (для журнала)
	state   string        // "", "connecting", "ready", "down"
	checked time.Time
	running bool
}

// installID — постоянный номер установки (для журнала разработчика).
func installID(dir string) string {
	p := filepath.Join(dir, "install-id")
	if b, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(b))) == 16 {
		return strings.TrimSpace(string(b))
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	_ = os.MkdirAll(dir, 0o700)
	_ = os.WriteFile(p, []byte(id), 0o600)
	return id
}

func (d *DevLink) Name() string { return StratDev }

func (d *DevLink) Enabled() bool { return d != nil && d.dialTo != nil }

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
					d.mu.Lock()
					rtt := d.rtt
					d.mu.Unlock()
					d.logf("На связи %s (отклик %d мс) — трафик идёт через него", d.label, rtt.Milliseconds())
				case "down":
					d.mu.Lock()
					why := d.lastErr
					d.mu.Unlock()
					d.logf("Сейчас недоступен %s (%s) — работает обычный режим", d.label, why)
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
		d.logf("Подключаюсь: %s", d.label)
	}
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		t0 := time.Now()
		c, err := d.socks(ctx, devPingHost, 1, false) // проверка — без запаса соединений
		cancel()
		if err == nil {
			c.Close()
			d.mu.Lock()
			d.rtt = time.Since(t0)
			d.mu.Unlock()
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

// Заранее открытые соединения: TCP и TLS до сервера готовы, остаётся только запрос.
// Сервер ждёт запрос 15 секунд, поэтому соединение старше warmMaxAge не используется.
type warmConn struct {
	c net.Conn
	t time.Time
}

const (
	warmMaxAge = 10 * time.Second
	warmCount  = 4
	warmActive = 30 * time.Second // держать запас, пока трафик шёл за последние 30 секунд
)

// takeConn — готовое соединение из запаса (или новое) и пополнение запаса в фоне.
func (d *DevLink) takeConn(ctx context.Context) (net.Conn, bool, error) {
	d.mu.Lock()
	d.lastUse = time.Now()
	var c net.Conn
	for len(d.pool) > 0 && c == nil {
		w := d.pool[0]
		d.pool = d.pool[1:]
		if time.Since(w.t) < warmMaxAge {
			c = w.c
		} else {
			w.c.Close()
		}
	}
	fill := !d.filling
	d.filling = true
	d.mu.Unlock()
	if fill {
		go d.fill()
	}
	if c != nil {
		return c, true, nil
	}
	c, err := d.dialTo(ctx)
	return c, false, err
}

// fill держит запас соединений, пока через сервер идёт трафик.
func (d *DevLink) fill() {
	defer func() { d.mu.Lock(); d.filling = false; d.mu.Unlock() }()
	for {
		d.mu.Lock()
		// выбросить устаревшие
		fresh := d.pool[:0]
		for _, w := range d.pool {
			if time.Since(w.t) < warmMaxAge {
				fresh = append(fresh, w)
			} else {
				w.c.Close()
			}
		}
		d.pool = fresh
		idle := time.Since(d.lastUse) > warmActive
		need := warmCount - len(d.pool)
		if idle {
			for _, w := range d.pool {
				w.c.Close()
			}
			d.pool = nil
			d.mu.Unlock()
			return
		}
		d.mu.Unlock()
		if need <= 0 {
			time.Sleep(time.Second)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		c, err := d.dialTo(ctx)
		cancel()
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		d.mu.Lock()
		d.pool = append(d.pool, warmConn{c, time.Now()})
		d.mu.Unlock()
	}
}

// dialSOCKS: TLS до сервера раздачи → SOCKS5 с логином → CONNECT host:port.
// Приветствие, логин и запрос отправляются одним пакетом: один обмен с сервером вместо трёх.
func (d *DevLink) dialSOCKS(ctx context.Context, host string, port int) (net.Conn, error) {
	return d.socks(ctx, host, port, true)
}

func (d *DevLink) socks(ctx context.Context, host string, port int, usePool bool) (net.Conn, error) {
	if len(host) > 255 {
		return nil, errors.New("слишком длинное имя")
	}
	user, pass := d.prefix+d.id, ""
	if d.Info != nil {
		pass = d.Info()
	}
	if len(pass) > 255 {
		pass = pass[:255]
	}
	msg := []byte{5, 1, 2, 1, byte(len(user))}
	msg = append(msg, user...)
	msg = append(append(msg, byte(len(pass))), pass...)
	msg = append(msg, 5, 1, 0)
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		msg = append(append(msg, 1), ip.To4()...)
	} else if ip != nil {
		msg = append(append(msg, 4), ip.To16()...)
	} else {
		msg = append(append(msg, 3, byte(len(host))), host...)
	}
	msg = binary.BigEndian.AppendUint16(msg, uint16(port))
	for attempt := 0; ; attempt++ {
		var c net.Conn
		var warm bool
		var err error
		if usePool {
			c, warm, err = d.takeConn(ctx)
		} else {
			c, err = d.dialTo(ctx)
		}
		if err != nil {
			return nil, fmt.Errorf("недоступен %s: %w", d.label, err)
		}
		c, err = d.socksOn(ctx, c, msg, host)
		if err == nil {
			return c, nil
		}
		var re *remoteErr
		if !warm || attempt > 0 || errors.As(err, &re) {
			return nil, err
		}
		// заготовленное соединение оказалось закрытым — ещё раз с новым
	}
}

// remoteErr — сервер ответил отказом (повторять бессмысленно).
type remoteErr struct{ msg string }

func (e *remoteErr) Error() string { return e.msg }

func (d *DevLink) socksOn(ctx context.Context, c net.Conn, msg []byte, host string) (net.Conn, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	fail := func(e error) (net.Conn, error) { c.Close(); return nil, e }
	if _, err := c.Write(msg); err != nil {
		return fail(err)
	}
	r := make([]byte, 2)
	if _, err := io.ReadFull(c, r); err != nil {
		return fail(err)
	}
	if r[1] != 2 {
		return fail(&remoteErr{"разработчик: неверный ответ"})
	}
	if _, err := io.ReadFull(c, r); err != nil {
		return fail(err)
	}
	if r[1] != 0 {
		return fail(&remoteErr{"разработчик не принял подключение"})
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return fail(err)
	}
	if hdr[1] != 0 {
		return fail(&remoteErr{fmt.Sprintf("разработчик: не удалось подключиться к %s (код %d)", host, hdr[1])})
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
