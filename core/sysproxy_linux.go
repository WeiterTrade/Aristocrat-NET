//go:build linux

package main

import (
	"errors"
	"os/exec"
	"strconv"
)

func hideWindow(cmd *exec.Cmd) {}

func gs(args ...string) error {
	return exec.Command("gsettings", append([]string{"set"}, args...)...).Run()
}

// SetSystemProxy работает в GNOME и производных (gsettings). В KDE и др. укажите прокси вручную.
func SetSystemProxy(port int) error {
	if _, err := exec.LookPath("gsettings"); err != nil {
		return errors.New("системный прокси автоматически настраивается только в GNOME; укажите прокси 127.0.0.1:" + strconv.Itoa(port) + " вручную")
	}
	p := strconv.Itoa(port)
	for _, k := range []string{"http", "https"} {
		if err := gs("org.gnome.system.proxy."+k, "host", "127.0.0.1"); err != nil {
			return err
		}
		if err := gs("org.gnome.system.proxy."+k, "port", p); err != nil {
			return err
		}
	}
	return gs("org.gnome.system.proxy", "mode", "manual")
}

func UnsetSystemProxy(port int) {
	if _, err := exec.LookPath("gsettings"); err == nil {
		_ = gs("org.gnome.system.proxy", "mode", "none")
	}
}
