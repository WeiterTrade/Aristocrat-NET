//go:build linux

package main

import (
	"os/exec"
	"syscall"
)

// bindChild: если «Обход» завершится, ядро Linux пошлёт tor SIGKILL.
func bindChild(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
}

func afterStart(cmd *exec.Cmd) {}
