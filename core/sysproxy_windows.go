//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"os/exec"
	"regexp"
	"syscall"
	"unsafe"
)

const inetKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
}

func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

var regVal = regexp.MustCompile(`ProxyServer\s+REG_SZ\s+(\S+)`)

func SetSystemProxy(port int) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if _, err := run("reg", "add", inetKey, "/v", "ProxyServer", "/t", "REG_SZ", "/d", addr, "/f"); err != nil {
		return err
	}
	_, _ = run("reg", "add", inetKey, "/v", "ProxyOverride", "/t", "REG_SZ", "/d", "localhost;127.*;10.*;192.168.*;<local>", "/f")
	if _, err := run("reg", "add", inetKey, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "1", "/f"); err != nil {
		return err
	}
	refreshInternetSettings()
	return nil
}

// UnsetSystemProxy выключает прокси, только если он указывает на нас.
func UnsetSystemProxy(port int) {
	out, err := run("reg", "query", inetKey, "/v", "ProxyServer")
	if err != nil {
		return
	}
	if m := regVal.FindStringSubmatch(out); m == nil || m[1] != fmt.Sprintf("127.0.0.1:%d", port) {
		return
	}
	_, _ = run("reg", "add", inetKey, "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f")
	refreshInternetSettings()
}

var (
	wininet            = syscall.NewLazyDLL("wininet.dll")
	internetSetOptionW = wininet.NewProc("InternetSetOptionW")
)

func refreshInternetSettings() {
	if internetSetOptionW.Find() != nil {
		return
	}
	_, _, _ = internetSetOptionW.Call(0, 39, 0, 0) // INTERNET_OPTION_SETTINGS_CHANGED
	_, _, _ = internetSetOptionW.Call(0, 37, 0, 0) // INTERNET_OPTION_REFRESH
}

// --- Привязка дочерних процессов (tor) к жизни программы -------------------

var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW     = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObj = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJob   = kernel32.NewProc("AssignProcessToJobObject")
	procOpenProcess          = kernel32.NewProc("OpenProcess")
	killJob                  uintptr
)

// JOBOBJECT_EXTENDED_LIMIT_INFORMATION: размер 112 байт на x86 и 144 на x64,
// поле LimitFlags — по смещению 16 на обеих архитектурах (выравнивание как в MSVC).
func jobLimitInfo() []byte {
	size := 144
	if unsafe.Sizeof(uintptr(0)) == 4 {
		size = 112
	}
	b := make([]byte, size)
	binary.LittleEndian.PutUint32(b[16:], 0x2000) // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	return b
}

func bindChild(cmd *exec.Cmd) {}

// afterStart помещает процесс в Job Object с KILL_ON_JOB_CLOSE:
// если «Обход» закроют или он упадёт, tor завершится вместе с ним (Windows 7+).
func afterStart(cmd *exec.Cmd) {
	if cmd.Process == nil || procCreateJobObjectW.Find() != nil {
		return
	}
	if killJob == 0 {
		h, _, _ := procCreateJobObjectW.Call(0, 0)
		if h == 0 {
			return
		}
		info := jobLimitInfo()
		r, _, _ := procSetInformationJobObj.Call(h, 9, uintptr(unsafe.Pointer(&info[0])), uintptr(len(info)))
		if r == 0 {
			return
		}
		killJob = h
	}
	const access = 0x0001 | 0x0100 // PROCESS_TERMINATE | PROCESS_SET_QUOTA
	ph, _, _ := procOpenProcess.Call(access, 0, uintptr(cmd.Process.Pid))
	if ph == 0 {
		return
	}
	_, _, _ = procAssignProcessToJob.Call(killJob, ph)
	_ = syscall.CloseHandle(syscall.Handle(ph))
}
