//go:build !windows

package main

// allowFirewall — на Linux порт открывается настройками системы (ufw/firewalld), если они включены.
func allowFirewall(port int) {}
