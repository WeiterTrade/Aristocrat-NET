//go:build windows

package main

import (
	"os"
	"os/exec"
	"strconv"
)

// allowFirewall — разрешить входящие подключения к раздаче в брандмауэре Windows.
// Нужны права администратора; без них правило ставит установщик сборки разработчика,
// а Windows сама спросит разрешение при первом открытии порта.
func allowFirewall(port int) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	name := "Aristocrat NET (раздача)"
	del := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
	hideWindow(del)
	_ = del.Run()
	add := exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name="+name, "dir=in", "action=allow",
		"protocol=TCP", "localport="+strconv.Itoa(port), "program="+exe, "enable=yes", "profile=any")
	hideWindow(add)
	_ = add.Run()
}
