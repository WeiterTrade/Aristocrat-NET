//go:build linux && gui

package main

// Нативный интерфейс Linux: окно программы (WebKitGTK) и значок в трее (StatusNotifierItem:
// Cinnamon/Mint, KDE, XFCE, MATE; в GNOME — с расширением AppIndicator).
// Закрытие окна сворачивает «Обход» в трей. Собирается с тегом gui и cgo.

import (
	_ "embed"
	"os"
	"os/exec"
	"strings"
	"sync"
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

	go enableGnomeTray(a.logf)
	start, end := systray.RunWithExternalLoop(func() {
		systray.SetIcon(trayPNG)
		systray.SetTitle(appTitle)
		systray.SetTooltip(appTitle)
		systray.SetOnTapped(request)
		mOpen := systray.AddMenuItem("Открыть "+appTitle, "")
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
						systray.SetTooltip(appTitle + " — шифрование включено")
					} else {
						mToggle.SetTitle("Включить обход")
						systray.SetTooltip(appTitle + " — выключено")
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
	// Окно создаётся один раз. «Свернуть в трей» только прячет его (главный цикл GTK продолжает
	// работать), а «Открыть» показывает снова. Раньше окно останавливало цикл GTK, оставаясь
	// на экране, — и система показывала «Aristocrat NET не отвечает».
	for {
		select {
		case <-done:
			return
		case <-showCh:
		}
		if !hasDisplay {
			continue
		}
		w := webview.New(false)
		if w == nil {
			a.logf("Не удалось создать окно WebKitGTK — открываю в браузере")
			openWindow(url)
			continue
		}
		w.SetTitle(appTitle)
		w.SetSize(460, 820, webview.HintNone)
		w.InterceptClose()
		w.Navigate(url)
		a.mu.Lock()
		a.hideUI = func() { w.Dispatch(w.Hide) }
		a.mu.Unlock()
		stop := make(chan struct{})
		quitting := false
		var qmu sync.Mutex
		go func() {
			for {
				select {
				case <-stop:
					return
				case <-done:
					qmu.Lock()
					quitting = true
					qmu.Unlock()
					w.Dispatch(w.Terminate) // из главного потока GTK
					return
				case <-showCh:
					w.Dispatch(w.Present) // показать (в том числе спрятанное в трей) окно
				}
			}
		}()
		w.Run() // до выхода из программы или пока окно не закрыли принудительно
		a.mu.Lock()
		a.hideUI = nil
		a.mu.Unlock()
		close(stop)
		w.Destroy()
		qmu.Lock()
		q := quitting
		qmu.Unlock()
		if q {
			return
		}
	}
}

// enableGnomeTray — в GNOME значки в трее показывает только расширение AppIndicator.
// Пакет программы ставит его как рекомендуемый (gnome-shell-extension-appindicator),
// а здесь оно включается для пользователя, если выключено.
func enableGnomeTray(logf func(string, ...any)) {
	de := strings.ToLower(os.Getenv("XDG_CURRENT_DESKTOP") + ":" + os.Getenv("DESKTOP_SESSION"))
	if !strings.Contains(de, "gnome") {
		return
	}
	if _, err := exec.LookPath("gnome-extensions"); err != nil {
		return
	}
	out, _ := exec.Command("gnome-extensions", "list").Output()
	enabled, _ := exec.Command("gnome-extensions", "list", "--enabled").Output()
	for _, uuid := range []string{"ubuntu-appindicators@ubuntu.com", "appindicatorsupport@rgcjonas.gmail.com"} {
		if strings.Contains(string(enabled), uuid) {
			return // уже работает
		}
	}
	for _, uuid := range []string{"appindicatorsupport@rgcjonas.gmail.com", "ubuntu-appindicators@ubuntu.com"} {
		if strings.Contains(string(out), uuid) {
			if err := exec.Command("gnome-extensions", "enable", uuid).Run(); err == nil {
				logf("GNOME: включено расширение для значков в трее (%s). Если значок не появился — выйдите из системы и войдите снова.", uuid)
			}
			return
		}
	}
	// Расширение только что поставлено вместе с программой — GNOME увидит его после повторного входа.
	_ = exec.Command("gsettings", "set", "org.gnome.shell", "disable-user-extensions", "false").Run()
	logf("GNOME: для значка в трее нужно расширение AppIndicator. Установите пакет gnome-shell-extension-appindicator и войдите в систему заново.")
}
