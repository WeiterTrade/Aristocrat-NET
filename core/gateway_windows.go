//go:build windows

package main

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"
)

// defaultGateway — адрес роутера сети, через которую компьютер выходит в интернет
// (при подключении к точке доступа телефона — это телефон). "" — не удалось узнать.
func defaultGateway() string {
	proc := syscall.NewLazyDLL("iphlpapi.dll").NewProc("GetBestRoute")
	if proc.Find() != nil {
		return ""
	}
	var row [14]uint32 // MIB_IPFORWARDROW
	dst := binary.LittleEndian.Uint32([]byte{8, 8, 8, 8})
	r, _, _ := proc.Call(uintptr(dst), 0, uintptr(unsafe.Pointer(&row[0])))
	if r != 0 {
		return ""
	}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, row[3]) // dwForwardNextHop
	ip := net.IP(b)
	if ip.IsUnspecified() || !ip.IsPrivate() {
		return ""
	}
	return ip.String()
}
