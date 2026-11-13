//go:build !windows && !(linux && gui)

package main

// На Linux и др. окно интерфейса открывается в браузере в режиме приложения (--app).
func runDesktopUI(a *App, url string, show bool, quit func(), done <-chan struct{}) {
	a.mu.Lock()
	a.showUI = func() { openWindow(url) }
	a.mu.Unlock()
	if show {
		openWindow(url)
	}
	<-done
}
