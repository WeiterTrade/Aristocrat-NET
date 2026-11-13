//go:build windows

package main

// Нативный интерфейс Windows 7–11 на Win32 (библиотека walk, без браузера и WebView2).
//   Главное окно: большая кнопка, состояние, страна и IP; «О программе» справа сверху,
//   шестерёнка настроек слева снизу. Закрытие окна сворачивает «Обход» в трей.

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	_ "image/png"
	"io"
	"math"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/lxn/walk"
	dcl "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
)

func init() {
	// walk требует, чтобы окна создавались и обслуживались в главном системном потоке.
	runtime.LockOSThread()
}

// Цвета (как в веб-версии).
var (
	colBg    = walk.RGB(0xF6, 0xF7, 0xF9)
	colText  = walk.RGB(0x1B, 0x1F, 0x24)
	colMuted = walk.RGB(0x6B, 0x73, 0x80)
	colOk    = walk.RGB(0x1F, 0x9D, 0x55)
	colOff   = walk.RGB(0x9A, 0xA3, 0xAF)
	colBusy  = walk.RGB(0x2F, 0x6F, 0xED)
	colWarn  = walk.RGB(0xC2, 0x41, 0x0C)
	colWhite = walk.RGB(0xFF, 0xFF, 0xFF)
	colLine  = walk.RGB(0xE4, 0xE7, 0xEC)
)

type nativeUI struct {
	a    *App
	quit func()

	mw           *walk.MainWindow
	cw           *walk.CustomWidget
	ni           *walk.NotifyIcon
	dlg          *walk.Dialog
	toggleAction *walk.Action

	fontBtn, fontState, fontSub, fontSmall, fontGear *walk.Font

	mu        sync.Mutex
	busy      bool
	errText   string
	ip, cc    string
	flag      *walk.Bitmap
	flagCC    string
	lastSig   string
	quitting  bool
	toldTray  bool
	circleBmp map[string]*walk.Bitmap

	// области для щелчков (в пикселях)
	rBtn, rGear, rAbout walk.Rectangle
}

func runDesktopUI(a *App, url string, show bool, quit func(), done <-chan struct{}) {
	u := &nativeUI{a: a, quit: quit, circleBmp: map[string]*walk.Bitmap{}}
	if err := u.build(); err != nil {
		// Если нативное окно не создалось — откатываемся на окно в браузере.
		a.logf("Не удалось создать окно: %v", err)
		a.mu.Lock()
		a.showUI = func() { openWindow(url) }
		a.mu.Unlock()
		if show {
			openWindow(url)
		}
		<-done
		return
	}
	a.mu.Lock()
	a.showUI = func() { u.mw.Synchronize(u.showWindow) }
	a.mu.Unlock()

	go func() {
		<-done
		u.mw.Synchronize(func() {
			u.mu.Lock()
			u.quitting = true
			u.mu.Unlock()
			if u.dlg != nil {
				u.dlg.Cancel()
			}
			u.ni.Dispose()
			u.mw.Close()
		})
	}()
	go u.ticker(done)
	go u.loadIP()

	if !show {
		u.mw.Starting().Attach(func() { u.mw.Hide() })
	}
	u.mw.Run()
}

func (u *nativeUI) build() error {
	var err error
	if u.fontBtn, err = walk.NewFont("Segoe UI", 15, walk.FontBold); err != nil {
		return err
	}
	u.fontState, _ = walk.NewFont("Segoe UI", 13, walk.FontBold)
	u.fontSub, _ = walk.NewFont("Segoe UI", 9, 0)
	u.fontSmall, _ = walk.NewFont("Segoe UI", 10, 0)
	u.fontGear, _ = walk.NewFont("Segoe UI Symbol", 17, 0)

	icon, _ := walk.NewIconFromResourceId(1)

	if err := (dcl.MainWindow{
		AssignTo:   &u.mw,
		Title:      "Обход",
		Icon:       icon,
		Size:       dcl.Size{Width: 440, Height: 640},
		MinSize:    dcl.Size{Width: 360, Height: 520},
		Layout:     dcl.VBox{MarginsZero: true, SpacingZero: true},
		Background: dcl.SolidColorBrush{Color: colBg},
		Children: []dcl.Widget{
			dcl.CustomWidget{
				AssignTo:            &u.cw,
				PaintPixels:         u.paint,
				ClearsBackground:    true,
				InvalidatesOnResize: true,
				DoubleBuffering:     true,
				Background:          dcl.SolidColorBrush{Color: colBg},
				OnMouseDown:         u.onMouseDown,
				OnMouseMove:         u.onMouseMove,
				OnKeyDown: func(key walk.Key) {
					if key == walk.KeyReturn || key == walk.KeySpace {
						u.toggle()
					}
				},
			},
		},
	}.Create()); err != nil {
		return err
	}
	if icon != nil {
		_ = u.mw.SetIcon(icon)
	}

	// Закрытие окна — сворачивание в трей.
	u.mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		u.mu.Lock()
		quitting := u.quitting
		tell := !u.toldTray
		u.toldTray = true
		u.mu.Unlock()
		if quitting {
			return
		}
		*canceled = true
		u.mw.Hide()
		if tell {
			_ = u.ni.ShowInfo("«Обход» продолжает работать", "Окно свёрнуто в трей. Щёлкните по значку, чтобы открыть его снова.")
		}
	})

	// Значок в трее.
	ni, err := walk.NewNotifyIcon(u.mw)
	if err != nil {
		return err
	}
	u.ni = ni
	if icon != nil {
		_ = ni.SetIcon(icon)
	}
	_ = ni.SetToolTip("Обход")
	ni.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			u.showWindow()
		}
	})
	add := func(text string, f func()) *walk.Action {
		act := walk.NewAction()
		_ = act.SetText(text)
		act.Triggered().Attach(f)
		_ = ni.ContextMenu().Actions().Add(act)
		return act
	}
	add("Открыть «Обход»", u.showWindow)
	u.toggleAction = add("Включить обход", u.toggle)
	_ = ni.ContextMenu().Actions().Add(walk.NewSeparatorAction())
	add("Настройки", func() { u.showWindow(); u.openSettings() })
	add("Выход", func() { go u.quit() })
	_ = ni.SetVisible(true)
	u.cw.SetFocus()
	return nil
}

func (u *nativeUI) showWindow() {
	u.mw.Show()
	win.ShowWindow(u.mw.Handle(), win.SW_RESTORE)
	_ = u.mw.Activate()
	win.SetForegroundWindow(u.mw.Handle())
}

// ticker раз в секунду проверяет состояние и перерисовывает окно при изменениях.
func (u *nativeUI) ticker(done <-chan struct{}) {
	lastOn := u.a.eng.Running()
	for {
		select {
		case <-done:
			return
		case <-time.After(time.Second):
		}
		on := u.a.eng.Running()
		if on != lastOn {
			lastOn = on
			go u.loadIP()
		}
		ts, tp, te := u.a.tor.Status()
		sig := fmt.Sprintf("%v|%s|%d|%s|%s|%s", on, ts, tp, te, u.a.proxyErr, u.settingsRoute())
		u.mu.Lock()
		changed := sig != u.lastSig
		u.lastSig = sig
		u.mu.Unlock()
		if changed {
			u.mw.Synchronize(func() {
				u.cw.Invalidate()
				if on {
					_ = u.toggleAction.SetText("Выключить обход")
					_ = u.ni.SetToolTip("Обход — шифрование включено")
				} else {
					_ = u.toggleAction.SetText("Включить обход")
					_ = u.ni.SetToolTip("Обход — выключен")
				}
			})
		}
	}
}

func (u *nativeUI) settingsRoute() string { return u.a.settings().Route }

func (u *nativeUI) toggle() {
	u.mu.Lock()
	if u.busy {
		u.mu.Unlock()
		return
	}
	u.busy, u.errText = true, ""
	u.mu.Unlock()
	u.cw.Invalidate()
	go func() {
		var err error
		if u.a.eng.Running() {
			u.a.disable()
		} else {
			err = u.a.enable()
		}
		u.mu.Lock()
		u.busy = false
		if err != nil {
			u.errText = err.Error()
		}
		u.mu.Unlock()
		u.mw.Synchronize(func() { u.cw.Invalidate() })
	}()
}

// loadIP узнаёт внешний IP и страну, загружает флаг.
func (u *nativeUI) loadIP() {
	u.mu.Lock()
	u.ip = "…"
	u.mu.Unlock()
	u.mw.Synchronize(func() { u.cw.Invalidate() })
	ip, cc, err := publicIP()
	if err != nil {
		ip = ""
	}
	var img image.Image
	u.mu.Lock()
	need := cc != "" && cc != u.flagCC
	u.mu.Unlock()
	if need {
		img = fetchFlag(cc)
	}
	u.mw.Synchronize(func() {
		u.mu.Lock()
		u.ip, u.cc = ip, cc
		if img != nil {
			if bmp, err := walk.NewBitmapFromImageForDPI(img, 96); err == nil {
				if u.flag != nil {
					u.flag.Dispose()
				}
				u.flag, u.flagCC = bmp, cc
			}
		}
		u.mu.Unlock()
		u.cw.Invalidate()
	})
}

// fetchFlag загружает картинку флага (флаги-эмодзи Windows не рисует).
func fetchFlag(cc string) image.Image {
	cl := &http.Client{Timeout: 6 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := cl.Get("https://flagcdn.com/48x36/" + strings.ToLower(cc) + ".png")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return nil
	}
	img, _, err := image.Decode(bytes.NewReader(b))
	if err != nil {
		return nil
	}
	return img
}

// circle рисует сглаженный круг с ободком (кнопка) и кэширует его.
func (u *nativeUI) circle(key string, size, ring int, fill, halo, bg walk.Color) *walk.Bitmap {
	k := fmt.Sprintf("%s|%d|%d", key, size, ring)
	if b, ok := u.circleBmp[k]; ok {
		return b
	}
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	c := float64(size) / 2
	rOuter, rInner := c, c-float64(ring)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			d := math.Hypot(float64(x)+0.5-c, float64(y)+0.5-c)
			col := mix(bg, halo, clamp01(rOuter-d+0.5))
			col = mix(col, fill, clamp01(rInner-d+0.5))
			img.Set(x, y, color.RGBA{col.R(), col.G(), col.B(), 255})
		}
	}
	bmp, err := walk.NewBitmapFromImageForDPI(img, 96)
	if err != nil {
		return nil
	}
	u.circleBmp[k] = bmp
	return bmp
}

func clamp01(v float64) float64 { return math.Max(0, math.Min(1, v)) }

func mix(a, b walk.Color, t float64) walk.Color {
	f := func(x, y byte) byte { return byte(float64(x) + (float64(y)-float64(x))*t + 0.5) }
	return walk.RGB(f(a.R(), b.R()), f(a.G(), b.G()), f(a.B(), b.B()))
}

func (u *nativeUI) paint(c *walk.Canvas, _ walk.Rectangle) error {
	b := u.cw.ClientBoundsPixels()
	s := float64(c.DPI()) / 96
	px := func(v float64) int { return int(v*s + 0.5) }
	bg, _ := walk.NewSolidColorBrush(colBg)
	defer bg.Dispose()
	_ = c.FillRectanglePixels(bg, b)

	on := u.a.eng.Running()
	st := u.a.settings()
	ts, tp, te := u.a.tor.Status()
	u.mu.Lock()
	busy, errText, ip, flag := u.busy, u.errText, u.ip, u.flag
	cc := u.cc
	u.mu.Unlock()

	// «О программе» — справа сверху.
	u.rAbout = walk.Rectangle{X: b.Width - px(130), Y: px(10), Width: px(118), Height: px(28)}
	_ = c.DrawTextPixels("О программе", u.fontSmall, colMuted, u.rAbout, walk.TextRight|walk.TextVCenter|walk.TextSingleLine)

	// Кнопка.
	d := px(196)
	ring := px(14)
	cx, cy := b.Width/2, int(float64(b.Height)*0.40)
	u.rBtn = walk.Rectangle{X: cx - d/2, Y: cy - d/2, Width: d, Height: d}
	fill, label, key := colOff, "Включить", "off"
	switch {
	case busy:
		fill, label, key = colBusy, "…", "busy"
	case on:
		fill, label, key = colOk, "Выключить", "on"
	}
	if bmp := u.circle(key, d, ring, fill, mix(colBg, fill, 0.18), colBg); bmp != nil {
		_ = c.DrawImagePixels(bmp, walk.Point{X: u.rBtn.X, Y: u.rBtn.Y})
	}
	_ = c.DrawTextPixels(label, u.fontBtn, colWhite, u.rBtn, walk.TextCenter|walk.TextVCenter|walk.TextSingleLine)

	// Состояние.
	y := u.rBtn.Y + d + px(26)
	state, stateCol := "Выключено", colText
	if on {
		state, stateCol = "Шифрование включено", colOk
	}
	_ = c.DrawTextPixels(state, u.fontState, stateCol, walk.Rectangle{X: 0, Y: y, Width: b.Width, Height: px(28)}, walk.TextCenter|walk.TextSingleLine)
	y += px(30)
	sub := "Трафик идёт как обычно"
	if on {
		sub = map[string]string{RouteAuto: "Обход блокировок + Tor при необходимости", RouteDPI: "Обход блокировок", RouteTor: "Весь трафик через Tor"}[st.Route]
		if st.Route != RouteDPI {
			switch ts {
			case "starting":
				sub += fmt.Sprintf("\nTor подключается… %d%%", tp)
			case "ready":
				sub += "\nTor подключён"
			}
		}
	}
	_ = c.DrawTextPixels(sub, u.fontSub, colMuted, walk.Rectangle{X: px(16), Y: y, Width: b.Width - px(32), Height: px(36)}, walk.TextCenter|walk.TextWordbreak)
	y += px(44)

	// IP и флаг.
	ipText := "Ваш IP: " + ip
	if ip == "" {
		ipText = "IP не определён"
	}
	if flag == nil && cc != "" && ip != "" && ip != "…" {
		ipText = "Ваш IP: " + cc + "  " + ip
	}
	fw, fh, gap := 0, 0, 0
	if flag != nil && ip != "" && ip != "…" {
		fw, fh, gap = px(24), px(18), px(8)
	}
	m, _, _ := c.MeasureTextPixels(ipText, u.fontSmall, walk.Rectangle{Width: b.Width, Height: px(30)}, walk.TextSingleLine)
	total := fw + gap + m.Width
	x0 := (b.Width - total) / 2
	if fw > 0 {
		_ = c.DrawImageStretchedPixels(flag, walk.Rectangle{X: x0, Y: y + (px(22)-fh)/2, Width: fw, Height: fh})
	}
	_ = c.DrawTextPixels(ipText, u.fontSmall, colText, walk.Rectangle{X: x0 + fw + gap, Y: y, Width: m.Width + px(4), Height: px(22)}, walk.TextLeft|walk.TextVCenter|walk.TextSingleLine)
	y += px(32)

	// Ошибки.
	var errs []string
	if errText != "" {
		errs = append(errs, errText)
	}
	if u.a.proxyErr != "" {
		errs = append(errs, u.a.proxyErr)
	}
	if on && st.Route != RouteDPI && ts == "error" && te != "" {
		errs = append(errs, te)
	}
	if len(errs) > 0 {
		_ = c.DrawTextPixels(strings.Join(errs, "\n"), u.fontSub, colWarn,
			walk.Rectangle{X: px(20), Y: y, Width: b.Width - px(40), Height: b.Height - y - px(80)}, walk.TextCenter|walk.TextWordbreak)
	}

	// Шестерёнка — слева снизу.
	g := px(52)
	u.rGear = walk.Rectangle{X: px(16), Y: b.Height - g - px(16), Width: g, Height: g}
	if bmp := u.circle("gear", g, px(1), walk.RGB(0xFF, 0xFF, 0xFF), colLine, colBg); bmp != nil {
		_ = c.DrawImagePixels(bmp, walk.Point{X: u.rGear.X, Y: u.rGear.Y})
	}
	_ = c.DrawTextPixels("⚙", u.fontGear, colMuted, u.rGear, walk.TextCenter|walk.TextVCenter|walk.TextSingleLine)
	return nil
}

func inRect(r walk.Rectangle, x, y int) bool {
	return x >= r.X && y >= r.Y && x < r.X+r.Width && y < r.Y+r.Height
}

func inCircle(r walk.Rectangle, x, y int) bool {
	cx, cy, rad := r.X+r.Width/2, r.Y+r.Height/2, r.Width/2
	dx, dy := x-cx, y-cy
	return dx*dx+dy*dy <= rad*rad
}

func (u *nativeUI) onMouseDown(x, y int, button walk.MouseButton) {
	if button != walk.LeftButton {
		return
	}
	switch {
	case inCircle(u.rBtn, x, y):
		u.toggle()
	case inCircle(u.rGear, x, y):
		u.openSettings()
	case inRect(u.rAbout, x, y):
		u.showAbout()
	}
}

func (u *nativeUI) onMouseMove(x, y int, _ walk.MouseButton) {
	if inCircle(u.rBtn, x, y) || inCircle(u.rGear, x, y) || inRect(u.rAbout, x, y) {
		u.cw.SetCursor(walk.CursorHand())
	} else {
		u.cw.SetCursor(walk.CursorArrow())
	}
}

func (u *nativeUI) showAbout() {
	walk.MsgBox(u.mw, "О программе", "Обход "+appVersion+"\n\n"+
		"Шифрует DNS и обходит блокировки провайдера прямо на компьютере — без VPN-подписок и своих серверов.\n\n"+
		"Сначала соединение идёт напрямую: начало защищённого соединения нарезается так, что фильтр провайдера (DPI) "+
		"не узнаёт сайт. Если сайт заблокирован по IP или обход не помог — соединение автоматически идёт через сеть Tor.\n\n"+
		"Используются: Tor и lyrebird (Tor Project). Лицензия MIT.", walk.MsgBoxIconInformation)
}

// ---------------------------------------------------------------------------
// Настройки

func indexOf(list []string, v string) int {
	for i, x := range list {
		if x == v {
			return i
		}
	}
	return 0
}

func (u *nativeUI) openSettings() {
	if u.dlg != nil {
		_ = u.dlg.Activate()
		return
	}
	st := u.a.settings()

	routeIDs := []string{RouteAuto, RouteDPI, RouteTor}
	routeNames := []string{RouteNames[RouteAuto], RouteNames[RouteDPI], RouteNames[RouteTor]}
	stratIDs := append([]string{"auto"}, AutoOrder...)
	stratNames := []string{"Авто"}
	for _, s := range AutoOrder {
		stratNames = append(stratNames, StratNames[s])
	}
	bridgeNames := make([]string, len(bridgeOrder))
	for i, b := range bridgeOrder {
		bridgeNames[i] = BridgeNames[b]
	}
	dohIDs := []string{"cloudflare", "google", "quad9"}
	dohNames := []string{"Cloudflare", "Google", "Quad9"}

	var (
		dlg                                *walk.Dialog
		cbRoute, cbStrat, cbBridges, cbDoH *walk.ComboBox
		teCustom, teTest, teSites, teLog   *walk.TextEdit
		btnSaveCustom, btnTest             *walk.PushButton
		leHost                             *walk.LineEdit
		chkSys, chkAuto                    *walk.CheckBox
		nePort                             *walk.NumberEdit
		lblTor                             *walk.Label
		ready                              bool
	)

	apply := func() {
		if !ready {
			return
		}
		s := u.a.settings()
		s.Route = routeIDs[cbRoute.CurrentIndex()]
		s.Mode = stratIDs[cbStrat.CurrentIndex()]
		s.Bridges = bridgeOrder[cbBridges.CurrentIndex()]
		s.DoH = dohIDs[cbDoH.CurrentIndex()]
		s.SysProxy = chkSys.Checked()
		s.AutoStart = chkAuto.Checked()
		s.Port = int(nePort.Value())
		custom := s.Bridges == "custom"
		teCustom.SetVisible(custom)
		btnSaveCustom.SetVisible(custom)
		cbBridges.SetEnabled(s.Route != RouteDPI)
		go func() {
			if err := u.a.applySettings(s); err != nil {
				u.mw.Synchronize(func() { walk.MsgBox(dlg, "Настройки", err.Error(), walk.MsgBoxIconWarning) })
			}
		}()
	}

	sites := func() string {
		var lines []string
		for h, r := range u.a.eng.Blocked() {
			lines = append(lines, "✗ "+h+" — "+r)
		}
		for h, s := range u.a.eng.Learned() {
			lines = append(lines, "✓ "+h+" — "+StratNames[s])
		}
		if len(lines) == 0 {
			return "Здесь появятся сайты, для которых понадобился особый метод или Tor."
		}
		return strings.Join(lines, "\r\n")
	}

	runTest := func() {
		host := strings.TrimSpace(leHost.Text())
		if host == "" {
			return
		}
		btnTest.SetEnabled(false)
		_ = teTest.SetText("Пробую все методы и Tor, до минуты…")
		go func() {
			res, err := u.a.eng.TestHost(host, false)
			var out string
			if err != nil {
				out = err.Error()
			} else {
				var lines []string
				for _, r := range res {
					mark := "✗"
					if r.OK {
						mark = fmt.Sprintf("✓ %d мс", r.Ms)
					}
					lines = append(lines, fmt.Sprintf("%-22s %s   %s", r.Name, mark, r.Info))
				}
				out = strings.Join(lines, "\r\n")
			}
			u.mw.Synchronize(func() {
				_ = teTest.SetText(out)
				btnTest.SetEnabled(true)
			})
		}()
	}

	err := dcl.Dialog{
		AssignTo: &dlg,
		Title:    "Настройки — Обход",
		MinSize:  dcl.Size{Width: 460, Height: 560},
		Size:     dcl.Size{Width: 520, Height: 760},
		Layout:   dcl.VBox{},
		Children: []dcl.Widget{
			dcl.ScrollView{
				HorizontalFixed: true,
				Layout:          dcl.VBox{},
				Children: []dcl.Widget{
					dcl.GroupBox{
						Title:  "Подключение",
						Layout: dcl.Grid{Columns: 2},
						Children: []dcl.Widget{
							dcl.Label{Text: "Маршрут:"},
							dcl.ComboBox{AssignTo: &cbRoute, Model: routeNames, CurrentIndex: indexOf(routeIDs, st.Route), OnCurrentIndexChanged: apply},
							dcl.Label{Text: "Метод обхода DPI:"},
							dcl.ComboBox{AssignTo: &cbStrat, Model: stratNames, CurrentIndex: indexOf(stratIDs, st.Mode), OnCurrentIndexChanged: apply},
							dcl.Label{Text: "Мосты Tor:"},
							dcl.ComboBox{AssignTo: &cbBridges, Model: bridgeNames, CurrentIndex: indexOf(bridgeOrder, st.Bridges), OnCurrentIndexChanged: apply},
							dcl.TextEdit{AssignTo: &teCustom, ColumnSpan: 2, MinSize: dcl.Size{Height: 70}, VScroll: true,
								Text: strings.ReplaceAll(st.CustomBridges, "\n", "\r\n"), Visible: st.Bridges == "custom",
								ToolTipText: "Строки мостов obfs4 или webtunnel, по одной в строке. Получить: Telegram-бот @GetBridgesBot"},
							dcl.PushButton{AssignTo: &btnSaveCustom, ColumnSpan: 2, Text: "Сохранить свои мосты", Visible: st.Bridges == "custom",
								OnClicked: func() {
									s := u.a.settings()
									s.CustomBridges = strings.ReplaceAll(teCustom.Text(), "\r\n", "\n")
									go func() { _ = u.a.applySettings(s) }()
								}},
							dcl.Label{AssignTo: &lblTor, ColumnSpan: 2, TextColor: colMuted},
						},
					},
					dcl.GroupBox{
						Title:  "Проверить сайт",
						Layout: dcl.VBox{},
						Children: []dcl.Widget{
							dcl.Composite{Layout: dcl.HBox{MarginsZero: true}, Children: []dcl.Widget{
								dcl.LineEdit{AssignTo: &leHost, CueBanner: "например, youtube.com", OnKeyDown: func(k walk.Key) {
									if k == walk.KeyReturn {
										runTest()
									}
								}},
								dcl.PushButton{AssignTo: &btnTest, Text: "Проверить", OnClicked: runTest},
							}},
							dcl.TextEdit{AssignTo: &teTest, ReadOnly: true, VScroll: true, MinSize: dcl.Size{Height: 110},
								Font: dcl.Font{Family: "Consolas", PointSize: 9}},
						},
					},
					dcl.GroupBox{
						Title:  "Сайты",
						Layout: dcl.VBox{},
						Children: []dcl.Widget{
							dcl.TextEdit{AssignTo: &teSites, ReadOnly: true, VScroll: true, MinSize: dcl.Size{Height: 80}, Text: sites()},
							dcl.PushButton{Text: "Забыть все сайты", OnClicked: func() {
								u.a.eng.Forget("")
								_ = teSites.SetText(sites())
							}},
						},
					},
					dcl.GroupBox{
						Title:  "Дополнительно",
						Layout: dcl.Grid{Columns: 2},
						Children: []dcl.Widget{
							dcl.Label{Text: "Шифрованный DNS:"},
							dcl.ComboBox{AssignTo: &cbDoH, Model: dohNames, CurrentIndex: indexOf(dohIDs, st.DoH), OnCurrentIndexChanged: apply},
							dcl.CheckBox{AssignTo: &chkSys, ColumnSpan: 2, Text: "Системный прокси (иначе укажите прокси 127.0.0.1 в программах)", Checked: st.SysProxy, OnCheckedChanged: apply},
							dcl.CheckBox{AssignTo: &chkAuto, ColumnSpan: 2, Text: "Включать обход при запуске программы", Checked: st.AutoStart, OnCheckedChanged: apply},
							dcl.Label{Text: "Порт прокси:"},
							dcl.NumberEdit{AssignTo: &nePort, Value: float64(st.Port), MinValue: 1024, MaxValue: 65535, Decimals: 0,
								OnValueChanged: apply},
						},
					},
					dcl.GroupBox{
						Title:  "Журнал",
						Layout: dcl.VBox{},
						Children: []dcl.Widget{
							dcl.TextEdit{AssignTo: &teLog, ReadOnly: true, VScroll: true, MinSize: dcl.Size{Height: 140},
								Font: dcl.Font{Family: "Consolas", PointSize: 8}},
						},
					},
				},
			},
			dcl.Composite{
				Layout: dcl.HBox{MarginsZero: true},
				Children: []dcl.Widget{
					dcl.PushButton{Text: "Выход из программы", OnClicked: func() {
						if walk.MsgBox(dlg, "Обход", "Выключить обход и закрыть программу?", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) == win.IDYES {
							go u.quit()
						}
					}},
					dcl.HSpacer{},
					dcl.PushButton{Text: "Закрыть", OnClicked: func() { dlg.Accept() }},
				},
			},
		},
	}.Create(u.mw)
	if err != nil {
		walk.MsgBox(u.mw, "Настройки", err.Error(), walk.MsgBoxIconError)
		return
	}
	cbBridges.SetEnabled(st.Route != RouteDPI)
	u.dlg = dlg
	ready = true

	// Обновление журнала и состояния Tor, пока окно открыто.
	stop := make(chan struct{})
	refresh := func() {
		u.a.mu.Lock()
		logs := strings.Join(u.a.logs, "\r\n")
		u.a.mu.Unlock()
		if teLog.Text() != logs {
			_ = teLog.SetText(logs)
			teLog.SendMessage(win.EM_LINESCROLL, 0, 100000)
		}
		ts, tp, te := u.a.tor.Status()
		t := ""
		switch ts {
		case "ready":
			t = "Tor подключён"
		case "starting":
			t = fmt.Sprintf("Tor подключается… %d%%", tp)
		case "error":
			t = te
		}
		_ = lblTor.SetText(t)
	}
	refresh()
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Second):
				dlg.Synchronize(refresh)
			}
		}
	}()
	dlg.Run()
	close(stop)
	u.dlg = nil
}
