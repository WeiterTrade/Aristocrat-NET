//go:build linux && gui

package main

// Нативный интерфейс Linux: окно программы (WebKitGTK) и значок в трее (StatusNotifierItem:
// Cinnamon/Mint, KDE, XFCE, MATE; в GNOME — с расширением AppIndicator).
// Закрытие окна сворачивает «Обход» в трей. Собирается с тегом gui и cgo.

import (
	_ "embed"
	"os"
	"time"

	"fyne.io/systray"

	"obhod/internal/webview"
)

//go:embed ui/tray.png
var trayPNG []byte

func runDesktopUI(a *App, url string, show bool, quit func(), done <-chan struct{}) {
	showCh := make(chan struct{}, 1)
	request := func() {
		select {
		case showCh <- struct{}{}:
		default:
		}
	}
	a.mu.Lock()
	a.showUI = request
	a.mu.Unlock()

	start, end := systray.RunWithExternalLoop(func() {
		systray.SetIcon(trayPNG)
		systray.SetTitle("Обход")
		systray.SetTooltip("Обход")
		systray.SetOnTapped(request)
		mOpen := systray.AddMenuItem("Открыть «Обход»", "")
		mToggle := systray.AddMenuItem("Включить обход", "")
		systray.AddSeparator()
		mQuit := systray.AddMenuItem("Выход", "")
		go func() {
			last := ""
			for {
				select {
				case <-done:
					return
				case <-mOpen.ClickedCh:
					request()
				case <-mToggle.ClickedCh:
					if a.eng.Running() {
						a.disable()
					} else if err := a.enable(); err != nil {
						a.logf("Не удалось включить: %v", err)
					}
				case <-mQuit.ClickedCh:
					go quit()
					return
				case <-time.After(time.Second):
				}
				state := "off"
				if a.eng.Running() {
					state = "on"
				}
				if state != last {
					last = state
					if state == "on" {
						mToggle.SetTitle("Выключить обход")
						systray.SetTooltip("Обход — шифрование включено")
					} else {
						mToggle.SetTitle("Включить обход")
						systray.SetTooltip("Обход — выключен")
					}
				}
			}
		}()
	}, nil)
	start()
	defer end()

	hasDisplay := os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	if show {
		request()
	}
	for {
		select {
		case <-done:
			return
		case <-showCh:
		}
		if !hasDisplay {
			continue
		}
		// Окно GTK живёт в главном потоке, пока его не закроют.
		w := webview.New(false)
		if w == nil {
			a.logf("Не удалось создать окно WebKitGTK — открываю в браузере")
			openWindow(url)
			continue
		}
		w.SetTitle("Обход")
		w.SetSize(460, 820, webview.HintNone)
		w.Navigate(url)
		stop := make(chan struct{})
		go func() {
			for {
				select {
				case <-stop:
					return
				case <-done:
					w.Terminate()
					return
				case <-showCh:
					w.Dispatch(w.Present) // повторный запуск — вывести окно вперёд
				}
			}
		}()
		w.Run()
		close(stop)
		w.Destroy()
	}
}
