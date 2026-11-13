//go:build linux

package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// bindChild: если «Обход» завершится, ядро Linux пошлёт tor SIGKILL.
func bindChild(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
}

func afterStart(cmd *exec.Cmd) {}

// killStaleTor завершает tor, оставшийся от прошлого запуска (по pid-файлу),
// только если это действительно наш tor (проверка пути исполняемого файла).
func killStaleTor(torExe, pidFile string) {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return
	}
	if exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe"); err == nil && exe == torExe {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		time.Sleep(300 * time.Millisecond)
	}
	_ = os.Remove(pidFile)
}
