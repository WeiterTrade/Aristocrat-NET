//go:build dev

package main

// Выход в интернет через компьютер разработчика без белого IP (например, в Казахстане):
//
//	пользователь → сервер раздачи (белый IP, Москва) → компьютер-выход → сайт.
//
// Компьютер-выход сам подключается к серверу и держит несколько готовых соединений.
// Когда пользователю нужен сайт, сервер отдаёт запрос в одно из них, компьютер-выход
// открывает сайт со своим IP и дальше просто передаёт данные. Пока выход не подключён,
// сервер открывает сайты сам.
//
// Вход выхода: логин «exit:» + ключ доступа сервера, пароль — производный от хэша пароля
// разработчика (есть только в сборках разработчика, в приложениях пользователей его нет).

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	exitUserPrefix = "exit:"
	exitSlots      = 12                // сколько готовых соединений держит компьютер-выход
	exitIdle       = 100 * time.Second // неиспользованное соединение выход заменяет новым
	exitMaxAge     = 90 * time.Second  // сервер берёт только соединения моложе этого
	exitWait       = 5 * time.Second   // сколько сервер ждёт свободного соединения
	exitRecent     = 2 * time.Minute   // выход «на связи», если подключался за это время
)

var errNoExit = errors.New("компьютер-выход не подключён")

// exitSecret — пароль выхода (пусто — в сборке нет пароля разработчика).
func exitSecret() string {
	if devPassHash == "" {
		return ""
	}
	m := hmac.New(sha256.New, []byte(devPassHash))
	m.Write([]byte("aristonet-exit-v1"))
	return hex.EncodeToString(m.Sum(nil))
}

// ---------------------------------------------------------------------------
// Сервер: принимает соединения от компьютера-выхода.

type exitConn struct {
	net.Conn
	r    io.Reader
	t    time.Time
	done chan struct{}
	once sync.Once
}

func (c *exitConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func (c *exitConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

func (c *exitConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

type exitPool struct {
	mu    sync.Mutex
	conns []*exitConn
	seen  time.Time
	from  string // IP компьютера-выхода
}

func (d *DevServer) holdExit(c net.Conn, br *bufio.Reader) {
	_ = c.SetDeadline(time.Time{})
	ec := &exitConn{Conn: c, r: br, t: time.Now(), done: make(chan struct{})}
	p := &d.exits
	ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	p.mu.Lock()
	first := time.Since(p.seen) > exitRecent
	p.conns = append(p.conns, ec)
	p.seen, p.from = time.Now(), ip
	p.mu.Unlock()
	if first {
		d.a.logf("Компьютер-выход подключился (%s): сайты открываются с его IP", ip)
		d.addJournal(fmt.Sprintf("%s · компьютер-выход подключился · IP %s", time.Now().Format("02.01 15:04"), ip))
	}
	t := time.NewTimer(exitIdle + 10*time.Second)
	defer t.Stop()
	select {
	case <-ec.done:
		return
	case <-t.C:
	}
	p.mu.Lock()
	for i, x := range p.conns {
		if x == ec {
			p.conns = append(p.conns[:i], p.conns[i+1:]...)
			p.mu.Unlock()
			ec.Close()
			return
		}
	}
	p.mu.Unlock()
	<-ec.done // уже используется — ждём конца
}

// takeExit — самое свежее соединение (nil — нет).
func (d *DevServer) takeExit() *exitConn {
	p := &d.exits
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.conns) > 0 {
		ec := p.conns[len(p.conns)-1]
		p.conns = p.conns[:len(p.conns)-1]
		if time.Since(ec.t) < exitMaxAge {
			return ec
		}
		go ec.Close()
	}
	return nil
}

func (d *DevServer) exitRecent() bool {
	d.exits.mu.Lock()
	defer d.exits.mu.Unlock()
	return time.Since(d.exits.seen) < exitRecent
}

// dialExit открывает сайт через компьютер-выход.
func (d *DevServer) dialExit(host string, port int) (net.Conn, error) {
	if !d.exitRecent() || len(host) > 255 {
		return nil, errNoExit
	}
	msg := []byte{5, 1, 0, 5, 1, 0}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		msg = append(append(msg, 1), ip.To4()...)
	} else if ip != nil {
		msg = append(append(msg, 4), ip.To16()...)
	} else {
		msg = append(append(msg, 3, byte(len(host))), host...)
	}
	msg = binary.BigEndian.AppendUint16(msg, uint16(port))
	end := time.Now().Add(exitWait)
	for tries := 0; tries < 6; {
		ec := d.takeExit()
		if ec == nil {
			if time.Now().After(end) {
				return nil, errNoExit
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		tries++
		c, err, remote := exitRequest(ec, msg)
		if err == nil {
			return c, nil
		}
		if remote {
			return nil, err
		}
	}
	return nil, errNoExit
}

// exitRequest — SOCKS5 без логина поверх соединения выхода (приветствие и запрос одним пакетом).
// remote — выход ответил отказом (сайт недоступен), повторять не нужно.
func exitRequest(c net.Conn, msg []byte) (net.Conn, error, bool) {
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	fail := func(e error, remote bool) (net.Conn, error, bool) { c.Close(); return nil, e, remote }
	if _, err := c.Write(msg); err != nil {
		return fail(err, false)
	}
	r := make([]byte, 2)
	if _, err := io.ReadFull(c, r); err != nil || r[1] != 0 {
		return fail(errors.New("выход: неверный ответ"), false)
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return fail(err, true)
	}
	if hdr[1] != 0 {
		return fail(fmt.Errorf("выход: сайт недоступен (код %d)", hdr[1]), true)
	}
	skip := 0
	switch hdr[3] {
	case 1:
		skip = 6
	case 4:
		skip = 18
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return fail(err, true)
		}
		skip = int(l[0]) + 2
	}
	if _, err := io.ReadFull(c, make([]byte, skip)); err != nil {
		return fail(err, true)
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil, false
}

// exitServerStatus — для строки состояния раздачи.
func (d *DevServer) exitServerStatus() string {
	p := &d.exits
	p.mu.Lock()
	defer p.mu.Unlock()
	if time.Since(p.seen) < exitRecent {
		return fmt.Sprintf("выход через компьютер %s (готово соединений: %d)", p.from, len(p.conns))
	}
	return "выход с IP этого сервера"
}

// ---------------------------------------------------------------------------
// Компьютер-выход: подключается к серверу «Ебаной Чукотки» и открывает сайты со своим IP.

type exitAgent struct {
	stop  chan struct{}
	eng   *Engine
	mu    sync.Mutex
	ready int
	err   string
	open  map[net.Conn]bool
}

// prefixConn возвращает сначала уже прочитанный байт.
type prefixConn struct {
	net.Conn
	pre []byte
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if len(c.pre) > 0 {
		n := copy(b, c.pre)
		c.pre = c.pre[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

func (c *prefixConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (d *DevServer) ExitOn() bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.agent != nil
}

func (d *DevServer) StartExit() error {
	if d.ExitOn() {
		return nil
	}
	if !directAvailable() {
		return errors.New("в этой сборке нет кода сервера (секрет DEV_DIRECT): пересоберите после его добавления")
	}
	if exitSecret() == "" {
		return errors.New("в сборке нет пароля разработчика (секрет DEV_PASSWORD)")
	}
	dl := NewDirectLink(d.a.dir, d.a.logf)
	tok := dl.prefix
	user, pass := exitUserPrefix+tok, exitSecret()
	auth := append([]byte{5, 1, 2, 1, byte(len(user))}, user...)
	auth = append(append(auth, byte(len(pass))), pass...)
	ag := &exitAgent{stop: make(chan struct{}), eng: d.shareEngine(nil), open: map[net.Conn]bool{}}
	d.mu.Lock()
	d.agent = ag
	d.mu.Unlock()
	d.a.sharing.Store(true)
	go d.a.startUpstreams(false)
	for i := 0; i < exitSlots; i++ {
		go ag.slot(dl, auth)
	}
	d.a.logf("Выход в интернет через этот компьютер включён (%s)", dl.label)
	return nil
}

func (ag *exitAgent) stopped() bool {
	select {
	case <-ag.stop:
		return true
	default:
		return false
	}
}

func (ag *exitAgent) sleep(t time.Duration) {
	select {
	case <-ag.stop:
	case <-time.After(t):
	}
}

func (ag *exitAgent) track(c net.Conn, on bool) {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	if on {
		ag.open[c] = true
	} else {
		delete(ag.open, c)
	}
}

func (ag *exitAgent) setErr(e string) {
	ag.mu.Lock()
	ag.err = e
	ag.mu.Unlock()
}

// slot держит одно готовое соединение с сервером; использованное сразу заменяется новым.
func (ag *exitAgent) slot(dl *DevLink, auth []byte) {
	for !ag.stopped() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		c, err := dl.dialTo(ctx)
		cancel()
		if err != nil {
			ag.setErr("нет связи с сервером: " + shortErr(err))
			ag.sleep(5 * time.Second)
			continue
		}
		ag.track(c, true)
		_ = c.SetDeadline(time.Now().Add(15 * time.Second))
		r := make([]byte, 4)
		_, werr := c.Write(auth)
		if werr == nil {
			_, werr = io.ReadFull(c, r)
		}
		if werr != nil || r[1] != 2 || r[3] != 0 {
			c.Close()
			ag.track(c, false)
			if werr == nil {
				ag.setErr("сервер не принял компьютер-выход: на сервере старая версия или другой пароль разработчика")
				ag.sleep(30 * time.Second)
			} else {
				ag.setErr("нет связи с сервером: " + shortErr(werr))
				ag.sleep(5 * time.Second)
			}
			continue
		}
		ag.mu.Lock()
		ag.ready++
		ag.err = ""
		ag.mu.Unlock()
		_ = c.SetDeadline(time.Now().Add(exitIdle))
		b := make([]byte, 1)
		_, err = io.ReadFull(c, b)
		ag.mu.Lock()
		ag.ready--
		ag.mu.Unlock()
		if err != nil {
			c.Close()
			ag.track(c, false)
			continue
		}
		_ = c.SetDeadline(time.Time{})
		go func() {
			ag.eng.handle(&prefixConn{Conn: c, pre: b})
			ag.track(c, false)
		}()
	}
}

func (d *DevServer) StopExit() {
	d.mu.Lock()
	ag := d.agent
	d.agent = nil
	d.mu.Unlock()
	if ag == nil {
		return
	}
	close(ag.stop)
	ag.mu.Lock()
	for c := range ag.open {
		c.Close()
	}
	ag.mu.Unlock()
	d.a.updSharing()
	d.a.logf("Выход в интернет через этот компьютер выключен")
}

func (d *DevServer) ExitStatus() string {
	d.mu.Lock()
	ag := d.agent
	d.mu.Unlock()
	if ag == nil {
		if !directAvailable() {
			return "Нет кода сервера в сборке (секрет DEV_DIRECT)"
		}
		return "Выключен"
	}
	ag.mu.Lock()
	defer ag.mu.Unlock()
	if ag.ready > 0 {
		return fmt.Sprintf("На связи с сервером (готово соединений: %d)", ag.ready)
	}
	if ag.err != "" {
		return ag.err
	}
	return "Подключаюсь к серверу…"
}
