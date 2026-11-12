//go:build darwin

package main

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

func hideWindow(cmd *exec.Cmd) {}

// services — активные сетевые службы (Wi-Fi, Ethernet…).
func services() []string {
	out, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil
	}
	var res []string
	for i, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if i == 0 || l == "" || strings.HasPrefix(l, "*") {
			continue
		}
		res = append(res, l)
	}
	return res
}

func SetSystemProxy(port int) error {
	p := strconv.Itoa(port)
	var errs []string
	for _, s := range services() {
		for _, k := range []string{"-setwebproxy", "-setsecurewebproxy"} {
			if out, err := exec.Command("networksetup", k, s, "127.0.0.1", p).CombinedOutput(); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %s", s, strings.TrimSpace(string(out))))
			}
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func UnsetSystemProxy(port int) {
	for _, s := range services() {
		_ = exec.Command("networksetup", "-setwebproxystate", s, "off").Run()
		_ = exec.Command("networksetup", "-setsecurewebproxystate", s, "off").Run()
	}
}
