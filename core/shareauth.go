package main

// Вход в прокси раздачи (сборка разработчика): SOCKS5 с логином и паролем.
// Логин — номер установки пользователя, пароль — сведения о нём (devInfo).
// Заодно считается трафик каждого пользователя для журнала разработчика.

import (
	"net"
	"sync/atomic"
)

type ShareClient struct {
	Up, Down, Active atomic.Int64
}

type ShareAuth struct {
	// Check — пускать ли пользователя; nil — нет.
	Check func(user, pass string) *ShareClient
}

// countConn считает байты соединения пользователя раздачи.
type countConn struct {
	net.Conn
	owner atomic.Pointer[ShareClient]
}

func (c *countConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if o := c.owner.Load(); o != nil && n > 0 {
		o.Up.Add(int64(n))
	}
	return n, err
}

func (c *countConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if o := c.owner.Load(); o != nil && n > 0 {
		o.Down.Add(int64(n))
	}
	return n, err
}

// CloseWrite — полузакрытие (конец ответа), как у обычного TCP-соединения.
func (c *countConn) CloseWrite() error {
	if tc, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return tc.CloseWrite()
	}
	return c.Conn.Close()
}
