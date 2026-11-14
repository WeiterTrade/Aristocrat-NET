module obhod

go 1.20

require (
	fyne.io/systray v1.12.2
	github.com/lxn/walk v0.0.0-20210112085537-c389da54e794
	github.com/lxn/win v0.0.0-20210218163916-a377121e959e
	golang.org/x/sys v0.15.0
	golang.org/x/net v0.7.0
	golang.zx2c4.com/wireguard v0.0.0-20231010133717-ec8f6f82c20c
	// gVisor для Go 1.20 (Windows 7). Сборки на Go 1.24 заменяют его свежим через go get.
	gvisor.dev/gvisor v0.0.0-20221203005347-703fd9b7fbc0
)

require (
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	gopkg.in/Knetic/govaluate.v3 v3.0.0 // indirect
)
