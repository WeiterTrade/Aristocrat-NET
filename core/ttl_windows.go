//go:build windows

package main

import (
	"net"
	"syscall"
)

const ipv6UnicastHops = 4 // IPV6_UNICAST_HOPS в Winsock

func isV6(c *net.TCPConn) bool {
	a, ok := c.RemoteAddr().(*net.TCPAddr)
	return ok && a.IP.To4() == nil
}

func setTTL(c *net.TCPConn, ttl int) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = rc.Control(func(fd uintptr) {
		if isV6(c) {
			serr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, ipv6UnicastHops, ttl)
		} else {
			serr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		}
	})
	if err != nil {
		return err
	}
	return serr
}

// В Windows TTL по умолчанию — 128.
func defaultTTL(c *net.TCPConn) int { return 128 }
