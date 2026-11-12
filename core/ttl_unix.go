//go:build !windows

package main

import (
	"net"
	"syscall"
)

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
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
		} else {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		}
	})
	if err != nil {
		return err
	}
	return serr
}

func defaultTTL(c *net.TCPConn) int {
	rc, err := c.SyscallConn()
	if err != nil {
		return 64
	}
	v := 64
	_ = rc.Control(func(fd uintptr) {
		var x int
		var e error
		if isV6(c) {
			x, e = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS)
		} else {
			x, e = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL)
		}
		if e == nil && x > 1 {
			v = x
		}
	})
	return v
}
