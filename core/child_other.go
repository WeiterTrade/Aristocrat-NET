//go:build !linux && !windows

package main

import "os/exec"

func bindChild(cmd *exec.Cmd)  {}
func afterStart(cmd *exec.Cmd) {}

func killStaleTor(torExe, pidFile string) {}
