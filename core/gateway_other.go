//go:build !windows

package main

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"os"
	"strings"
)

// defaultGateway — адрес роутера сети по умолчанию (Linux: /proc/net/route). "" — не удалось узнать.
func defaultGateway() string {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(l)
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		g, err := hex.DecodeString(f[2])
		if err != nil || len(g) != 4 {
			continue
		}
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, binary.BigEndian.Uint32(g))
		if ip.IsPrivate() {
			return ip.String()
		}
	}
	return ""
}
