//go:build windows

package main

// Настройки в стиле мобильных приложений: страницы со списками строк (переход «›»,
// переключатели, выбор из списка), всё рисуется программой в цветах Aristocrat NET.
// Поля ввода (свои мосты, проверка сайта, порт, журнал) — настоящие поля Windows,
// перекрашенные и вставленные в рамки страницы.

import (
	"fmt"
	"image"
	"math"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lxn/walk"
	"github.com/lxn/win"
)

const (
	kStatus = iota
	kSection
	kRow
	kText
	kNative
	kButtons
)

type sBtn struct {
	label   string
	primary bool
	act     func()
	r       walk.Rectangle
}

type sItem struct {
	kind              int
	title, sub, value string
	toggle, on        bool
	radio, selected   bool
	nav, danger       bool
	act               func()
	native            walk.Widget
	h                 int // высота поля ввода, DIP; 0 — до низа страницы
	btns              []*sBtn
	lines, warns      []string
	r                 walk.Rectangle
	first, last       bool
}

type sPage struct {
	title, parent string
	items         []*sItem
}

// ---------------------------------------------------------------------------
// Страницы

func (u *nativeUI) apply(change func(s *Settings)) {
	s := u.a.settings()
	change(&s)
	go func() {
		err := u.a.applySettings(s)
		u.mw.Synchronize(func() {
			if err != nil {
				walk.MsgBox(u.mw, appTitle, err.Error(), walk.MsgBoxIconWarning)
			}
			u.setPane.Invalidate()
			u.home.Invalidate()
		})
	}()
}

func row(title, sub, value string, act func()) *sItem {
	return &sItem{kind: kRow, title: title, sub: sub, value: value, nav: true, act: act}
}

func toggleRow(title, sub string, on bool, act func()) *sItem {
	return &sItem{kind: kRow, title: title, sub: sub, toggle: true, on: on, act: act}
}

func section(title string) *sItem { return &sItem{kind: kSection, title: title} }

func (u *nativeUI) open(page string) func() {
	return func() {
		u.page, u.scroll = page, 0
		u.showPage()
	}
}

// radioPage — выбор одного значения из списка; после выбора — назад.
func (u *nativeUI) radioPage(title string, ids []string, names map[string]string, hints map[string]string, cur string, set func(s *Settings, v string)) sPage {
	p := sPage{title: title, parent: "root", items: []*sItem{section(title)}}
	for _, id := range ids {
		id := id
		p.items = append(p.items, &sItem{kind: kRow, title: names[id], sub: hints[id], radio: true, selected: id == cur,
			act: func() {
				u.apply(func(s *Settings) { set(s, id) })
				u.goBack()
			}})
	}
	return p
}

var routeHints = map[string]string{
	RouteAuto: "Сайты напрямую с обходом DPI; заблокированные по IP — через WARP или Tor",
	RouteDPI:  "Самый быстрый: без смены IP, без WARP и Tor",
	RouteWarp: "Весь трафик через Cloudflare: другой IP, быстро (страна остаётся вашей)",
	RouteTor:  "Весь трафик через Tor: IP другой страны, медленнее",
}

var dohIDs = []string{"cloudflare", "google", "quad9"}
var dohNames = map[string]string{"cloudflare": "Cloudflare (1.1.1.1)", "google": "Google (8.8.8.8)", "quad9": "Quad9 (9.9.9.9)"}

func (u *nativeUI) buildPage(id string) sPage {
	st := u.a.settings()
	switch id {
	case "route":
		return u.radioPage("Режим работы", []string{RouteAuto, RouteDPI, RouteWarp, RouteTor}, RouteNames, routeHints, st.Route,
			func(s *Settings, v string) { s.Route = v })
	case "heavy":
		return u.radioPage("Если сайт заблокирован по IP", heavyOrder, HeavyNames, map[string]string{
			HeavyWarpTor: "WARP быстрее; Tor — запасной вариант",
		}, st.Heavy, func(s *Settings, v string) { s.Heavy = v })
	case "strat":
		ids := append([]string{"auto"}, AutoOrder...)
		names := map[string]string{"auto": "Авто — подбирать для каждого сайта"}
		for k, v := range StratNames {
			names[k] = v
		}
		return u.radioPage("Метод обхода DPI", ids, names, nil, st.Mode, func(s *Settings, v string) { s.Mode = v })
	case "doh":
		return u.radioPage("Шифрованный DNS", dohIDs, dohNames, nil, st.DoH, func(s *Settings, v string) { s.DoH = v })
	case "bridges":
		return u.radioPage("Мосты Tor", bridgeOrder, BridgeNames, map[string]string{
			"auto":   "Сначала snowflake, при неудаче — obfs4 и meek; свои мосты — всегда",
			"custom": "Только мосты из Telegram-бота @GetBridgesBot",
		}, st.Bridges, func(s *Settings, v string) { s.Bridges = v })
	case "country":
		return u.radioPage("Страна IP через Tor", torCountryOrder, TorCountries, nil, st.TorCountry,
			func(s *Settings, v string) { s.TorCountry = v })
	case "custom":
		return sPage{title: "Свои мосты", parent: "root", items: []*sItem{
			{kind: kText, title: "Мосты WebTunnel или obfs4 из Telegram-бота @GetBridgesBot, по одному в строке. " +
				"Перед запуском программа проверит их и возьмёт самые быстрые."},
			{kind: kNative, native: u.teBridges, h: 230},
			{kind: kButtons, btns: []*sBtn{{label: "Сохранить", primary: true, act: func() {
				text := strings.ReplaceAll(u.teBridges.Text(), "\r\n", "\n")
				u.apply(func(s *Settings) { s.CustomBridges = text })
				u.showToast("Мосты сохранены")
			}}}},
		}}
	case "test":
		label := "Проверить"
		if u.testing {
			label = "Проверяю…"
		}
		return sPage{title: "Проверить сайт", parent: "root", items: []*sItem{
			{kind: kText, title: "Программа попробует открыть сайт всеми способами: напрямую, каждым методом обхода, через WARP и Tor."},
			{kind: kNative, native: u.leHost, h: 30},
			{kind: kButtons, btns: []*sBtn{{label: label, primary: true, act: u.runTest}}},
			{kind: kNative, native: u.teResult},
		}}
	case "sites":
		return sPage{title: "Подобранные сайты", parent: "root", items: []*sItem{
			{kind: kButtons, btns: []*sBtn{{label: "Забыть все", act: func() {
				u.a.eng.Forget("")
				u.a.save()
				u.refreshPage()
				u.showToast("Список очищен")
			}}}},
			{kind: kNative, native: u.teSites},
		}}
	case "port":
		return sPage{title: "Порт прокси", parent: "root", items: []*sItem{
			{kind: kNative, native: u.lePort, h: 30},
			{kind: kButtons, btns: []*sBtn{{label: "Сохранить", primary: true, act: func() {
				p, err := strconv.Atoi(strings.TrimSpace(u.lePort.Text()))
				if err != nil || p < 1024 || p > 65535 {
					walk.MsgBox(u.mw, appTitle, "Порт — число от 1024 до 65535", walk.MsgBoxIconWarning)
					return
				}
				u.apply(func(s *Settings) { s.Port = p })
				u.showToast("Порт сохранён")
			}}}},
			{kind: kText, title: "Если «Системный прокси» выключен, укажите в браузере прокси 127.0.0.1 и этот порт (HTTP или SOCKS5)."},
		}}
	case "logs":
		return sPage{title: "Журнал", parent: "root", items: []*sItem{
			{kind: kButtons, btns: []*sBtn{
				{label: "Копировать", primary: true, act: func() {
					if err := walk.Clipboard().SetText(u.logText()); err == nil {
						u.showToast("Журнал скопирован")
					}
				}},
				{label: "Очистить", act: func() {
					u.a.mu.Lock()
					u.a.logs = nil
					u.a.mu.Unlock()
					u.refreshPage()
				}},
			}},
			{kind: kNative, native: u.teLog},
		}}
	}

	// Главная страница настроек
	lines, warns := u.a.upstreamLines()
	status := []string{"Выключено"}
	if u.a.eng.Running() {
		status = append([]string{routeSummary(st)}, lines...)
	}
	_, needTor := st.needs()
	items := []*sItem{
		{kind: kStatus, lines: status, warns: warns},
		section("Подключение"),
		row("Режим работы", routeHints[st.Route], shortRoute(st.Route), u.open("route")),
	}
	if st.Route == RouteAuto {
		items = append(items, row("Если сайт заблокирован по IP", "", HeavyNames[st.Heavy], u.open("heavy")))
	}
	stratName := "Авто"
	if st.Mode != "auto" {
		stratName = StratNames[st.Mode]
	}
	items = append(items,
		row("Метод обхода DPI", "", stratName, u.open("strat")),
		row("Шифрованный DNS", "", strings.Split(dohNames[st.DoH], " ")[0], u.open("doh")),
	)
	if needTor || st.GeoTor {
		country := TorCountries[st.TorCountry]
		if st.TorCountry == "" {
			country = "Любая"
		}
		items = append(items,
			section("Tor"),
			row("Мосты Tor", "", BridgeNames[st.Bridges], u.open("bridges")),
			row("Свои мосты", "", bridgeCount(st.CustomBridges), u.open("custom")),
			row("Страна IP через Tor", "", country, u.open("country")),
		)
	}
	learned := len(u.a.eng.Learned()) + len(u.a.eng.Blocked())
	items = append(items,
		section("Правила"),
		toggleRow("Российские и казахстанские сайты — напрямую", "С настоящим IP даже через Tor и WARP: банки, госуслуги, Яндекс, VK",
			st.KeepLocal, func() { u.apply(func(s *Settings) { s.KeepLocal = !s.KeepLocal }) }),
		toggleRow("Spotify через Tor в России", "Сервисы, закрытые для России, — через Tor даже в «Авто»",
			st.GeoTor, func() { u.apply(func(s *Settings) { s.GeoTor = !s.GeoTor }) }),
		section("Инструменты"),
		row("Проверить сайт", "", "", u.open("test")),
		row("Подобранные сайты", "", strconv.Itoa(learned), u.open("sites")),
		section("Система"),
		toggleRow("Системный прокси", "Браузеры и программы сами идут через "+appTitle,
			st.SysProxy, func() { u.apply(func(s *Settings) { s.SysProxy = !s.SysProxy }) }),
		toggleRow("Включать при запуске", "", st.AutoStart, func() { u.apply(func(s *Settings) { s.AutoStart = !s.AutoStart }) }),
		row("Порт прокси", "", strconv.Itoa(st.Port), u.open("port")),
		section("Другие"),
		row("Журнал", "", "", u.open("logs")),
		row("О программе", "", "v"+appVersion, func() { u.aboutFromSettings = true; u.setView(viewAbout) }),
		&sItem{kind: kRow, title: "Выход из программы", danger: true, act: func() {
			if walk.MsgBox(u.mw, appTitle, "Выключить защиту и закрыть программу?", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) == win.IDYES {
				go u.quit()
			}
		}},
	)
	return sPage{title: "Настройки", items: items}
}

func shortRoute(r string) string {
	return map[string]string{RouteAuto: "Авто", RouteDPI: "Только DPI", RouteWarp: "WARP", RouteTor: "Tor"}[r]
}

func bridgeCount(custom string) string {
	n := 0
	for _, l := range strings.Split(custom, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			n++
		}
	}
	if n == 0 {
		return "нет"
	}
	return strconv.Itoa(n)
}

func (u *nativeUI) pageTitle() string {
	if u.page == "" || u.page == "root" {
		return "Настройки"
	}
	return u.buildPage(u.page).title
}

// goBack — стрелка «назад» в заголовке и Esc.
func (u *nativeUI) goBack() {
	switch {
	case u.view == viewAbout && u.aboutFromSettings:
		u.aboutFromSettings = false
		u.setView(viewSettings)
	case u.view == viewSettings && u.page != "root" && u.page != "":
		u.page, u.scroll = "root", 0
		u.showPage()
	default:
		u.setView(viewHome)
	}
}

// ---------------------------------------------------------------------------
// Поля ввода

func (u *nativeUI) allNatives() []walk.Widget {
	return []walk.Widget{u.teBridges, u.leHost, u.teResult, u.lePort, u.teLog, u.teSites}
}

// styleNatives — тёмные поля без системной рамки (рамку рисует страница).
func (u *nativeUI) styleNatives() {
	bg, _ := walk.NewSolidColorBrush(cCard.walk())
	for _, w := range u.allNatives() {
		w.SetBackground(bg)
		switch t := w.(type) {
		case *walk.TextEdit:
			t.SetTextColor(cText.walk())
		case *walk.LineEdit:
			t.SetTextColor(cText.walk())
		}
		h := w.Handle()
		ex := win.GetWindowLong(h, win.GWL_EXSTYLE)
		win.SetWindowLong(h, win.GWL_EXSTYLE, ex&^win.WS_EX_CLIENTEDGE)
		st := win.GetWindowLong(h, win.GWL_STYLE)
		win.SetWindowLong(h, win.GWL_STYLE, st&^win.WS_BORDER)
		win.SetWindowPos(h, 0, 0, 0, 0, 0, win.SWP_FRAMECHANGED|win.SWP_NOMOVE|win.SWP_NOSIZE|win.SWP_NOZORDER)
	}
}

func (u *nativeUI) logText() string {
	u.a.mu.Lock()
	defer u.a.mu.Unlock()
	return strings.Join(u.a.logs, "\r\n")
}

func (u *nativeUI) sitesText() string {
	var lines []string
	for h, r := range u.a.eng.Blocked() {
		lines = append(lines, "✗ "+h+" — "+r)
	}
	for h, s := range u.a.eng.Learned() {
		lines = append(lines, "✓ "+h+" — "+StratNames[s])
	}
	sort.Strings(lines)
	if len(lines) == 0 {
		return "Здесь появятся сайты, для которых понадобился особый метод, WARP или Tor."
	}
	return strings.Join(lines, "\r\n")
}

// showPage — переход на страницу: заполнить поля, расставить их, перерисовать.
func (u *nativeUI) showPage() {
	if u.page == "" {
		u.page = "root"
	}
	st := u.a.settings()
	switch u.page {
	case "custom":
		_ = u.teBridges.SetText(strings.ReplaceAll(st.CustomBridges, "\n", "\r\n"))
	case "port":
		_ = u.lePort.SetText(strconv.Itoa(st.Port))
	case "logs":
		_ = u.teLog.SetText(u.logText())
		u.teLog.SendMessage(win.EM_LINESCROLL, 0, 100000)
	case "sites":
		_ = u.teSites.SetText(u.sitesText())
	}
	u.layoutPage()
	u.setPane.Invalidate()
	u.title.Invalidate()
}

// refreshPage — раз в секунду, пока открыты настройки.
func (u *nativeUI) refreshPage() {
	switch u.page {
	case "logs":
		if t := u.logText(); u.teLog.Text() != t {
			_ = u.teLog.SetText(t)
			u.teLog.SendMessage(win.EM_LINESCROLL, 0, 100000)
		}
	case "sites":
		if t := u.sitesText(); u.teSites.Text() != t {
			_ = u.teSites.SetText(t)
		}
	}
	u.setPane.Invalidate()
}

func (u *nativeUI) showToast(t string) {
	u.toast, u.toastAt = t, time.Now()
	u.setPane.Invalidate()
	time.AfterFunc(2200*time.Millisecond, func() { u.mw.Synchronize(func() { _ = u.setPane.Invalidate() }) })
}

func (u *nativeUI) runTest() {
	host := strings.TrimSpace(u.leHost.Text())
	if host == "" || u.testing {
		return
	}
	u.testing = true
	_ = u.teResult.SetText("Пробую все методы, WARP и Tor — до минуты…")
	u.layoutPage()
	u.setPane.Invalidate()
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
				lines = append(lines, fmt.Sprintf("%s: %s  %s", r.Name, mark, r.Info))
			}
			out = strings.Join(lines, "\r\n")
		}
		u.mw.Synchronize(func() {
			u.testing = false
			_ = u.teResult.SetText(out)
			u.layoutPage()
			u.setPane.Invalidate()
		})
	}()
}

// ---------------------------------------------------------------------------
// Раскладка

func (u *nativeUI) textHeight(text string, f win.HFONT, width int) int {
	hdc := win.GetDC(0)
	defer win.ReleaseDC(0, hdc)
	old := win.SelectObject(hdc, win.HGDIOBJ(f))
	defer win.SelectObject(hdc, old)
	t, _ := syscall.UTF16FromString(text)
	rc := win.RECT{Right: int32(width)}
	win.DrawTextEx(hdc, &t[0], int32(len(t)-1), &rc, dtWord|dtNoPrefix|0x400 /*DT_CALCRECT*/, nil)
	return int(rc.Bottom - rc.Top)
}

func (u *nativeUI) textWidth(text string, f win.HFONT) int {
	hdc := win.GetDC(0)
	defer win.ReleaseDC(0, hdc)
	w, _ := u.txt.measure(hdc, text, f)
	return w
}

func (u *nativeUI) fonts() (title, sub, value, sect, btn win.HFONT) {
	s := u.dpiScale()
	return u.txt.font("Segoe UI", int(14*s), false), u.txt.font("Segoe UI", int(12*s), false),
		u.txt.font("Segoe UI", int(13*s), false), u.txt.font("Segoe UI Semibold", int(13*s), false),
		u.txt.font("Segoe UI Semibold", int(14*s), false)
}

// layoutPage строит текущую страницу и считает места всех элементов (и полей ввода).
func (u *nativeUI) layoutPage() {
	if u.setPane == nil {
		return
	}
	b := u.setPane.ClientBoundsPixels()
	s := u.dpiScale()
	p := u.buildPage(u.page)
	fT, fS, _, _, fB := u.fonts()
	pad, y := int(16*s), int(12*s)
	w := b.Width - 2*pad
	hasNative := false
	for _, it := range p.items {
		if it.kind == kNative {
			hasNative = true
		}
	}
	if hasNative {
		u.scroll = 0
	}
	var prev *sItem
	for i, it := range p.items {
		switch it.kind {
		case kStatus:
			fs := u.txt.font("Segoe UI", int(13*s), false)
			h := int(20 * s)
			for _, l := range append(append([]string{}, it.lines...), it.warns...) {
				h += u.textHeight(l, fs, w-int(28*s)) + int(2*s)
			}
			it.r = walk.Rectangle{X: pad, Y: y, Width: w, Height: h}
			y += h + int(6*s)
		case kSection:
			y += int(14 * s)
			it.r = walk.Rectangle{X: pad + int(4*s), Y: y, Width: w, Height: int(24 * s)}
			y += int(28 * s)
		case kRow:
			rh := int(50 * s)
			if it.sub != "" {
				rh = int(52*s) + u.textHeight(it.sub, fS, w-int(110*s))
			}
			_ = fT
			it.first = prev == nil || prev.kind != kRow
			it.r = walk.Rectangle{X: pad, Y: y, Width: w, Height: rh}
			y += rh
			next := (*sItem)(nil)
			if i+1 < len(p.items) {
				next = p.items[i+1]
			}
			it.last = next == nil || next.kind != kRow
		case kText:
			fs := u.txt.font("Segoe UI", int(13*s), false)
			h := u.textHeight(it.title, fs, w-int(8*s))
			it.r = walk.Rectangle{X: pad + int(4*s), Y: y, Width: w - int(8*s), Height: h}
			y += h + int(12*s)
		case kButtons:
			x := pad
			for _, bt := range it.btns {
				tw := u.textWidth(bt.label, fB)
				bw := tw + int(44*s)
				bt.r = walk.Rectangle{X: x, Y: y, Width: bw, Height: int(40 * s)}
				x += bw + int(10*s)
			}
			it.r = walk.Rectangle{X: pad, Y: y, Width: w, Height: int(40 * s)}
			y += int(52 * s)
		case kNative:
			h := int(float64(it.h) * s)
			if it.h == 0 {
				h = b.Height - y - pad - int(12*s)
				if h < int(120*s) {
					h = int(120 * s)
				}
			}
			it.r = walk.Rectangle{X: pad, Y: y, Width: w, Height: h + int(16*s)}
			y += h + int(16*s) + int(12*s)
		}
		prev = it
	}
	y += int(20 * s)
	if max := y - b.Height; u.scroll > max {
		u.scroll = int(math.Max(0, float64(max)))
	}
	// Поля ввода: только на своей странице, в рамке страницы.
	pb := u.setPane.BoundsPixels()
	shown := map[win.HWND]bool{}
	in := int(8 * s)
	for _, it := range p.items {
		if it.kind != kNative || it.native == nil {
			continue
		}
		r := walk.Rectangle{X: pb.X + it.r.X + in, Y: pb.Y + it.r.Y + in - u.scroll, Width: it.r.Width - 2*in, Height: it.r.Height - 2*in}
		u.natives[it.native.Handle()] = r
		shown[it.native.Handle()] = true
		if it.native.BoundsPixels() != r {
			_ = it.native.SetBoundsPixels(r)
		}
	}
	for _, n := range u.allNatives() {
		vis := u.view == viewSettings && shown[n.Handle()]
		if !vis {
			delete(u.natives, n.Handle())
		}
		if n.Visible() != vis {
			n.SetVisible(vis)
		}
	}
	u.setItems = p.items
	u.contentH = y
}

func (u *nativeUI) scrollBy(d int) {
	b := u.setPane.ClientBoundsPixels()
	max := u.contentH - b.Height
	if max < 0 {
		max = 0
	}
	n := u.scroll + d
	if n < 0 {
		n = 0
	}
	if n > max {
		n = max
	}
	if n != u.scroll {
		u.scroll = n
		u.setPane.Invalidate()
	}
}

// ---------------------------------------------------------------------------
// Рисование

func roundRectGrad(img *image.RGBA, r walk.Rectangle, rad float64, top, bottom, stroke rgb) {
	roundRectFill(img, r, rad, func(y int) rgb {
		return lerp(top, bottom, clamp01(float64(y-r.Y)/float64(r.Height)))
	}, stroke)
}

func shift(r walk.Rectangle, dy int) walk.Rectangle { r.Y -= dy; return r }

func (u *nativeUI) paintSettings(c *walk.Canvas, _ walk.Rectangle) error {
	b := u.setPane.ClientBoundsPixels()
	if !u.setOff.ensure(b.Width, b.Height) {
		return nil
	}
	u.drawSettings(&u.setOff, b)
	u.setOff.blit(c)
	return nil
}

func (u *nativeUI) drawSettings(o *offscreen, b walk.Rectangle) {
	if u.setItems == nil || u.lastPaneW != b.Width || u.lastPaneH != b.Height {
		u.lastPaneW, u.lastPaneH = b.Width, b.Height
		u.layoutPage()
	} else {
		// значения (статус, переключатели) могли измениться — пересобираем, места те же
		u.layoutPage()
	}
	s := u.dpiScale()
	sc := u.scroll
	img := o.img
	// фон: тёмный с лёгким синим свечением сверху (считается один раз на размер окна)
	if k := [2]int{b.Width, b.Height}; u.setBg == nil || u.setBgKey != k {
		u.setBg, u.setBgKey = image.NewRGBA(img.Bounds()), k
		for y := 0; y < b.Height; y++ {
			col := lerp(cBgGrad, cBg, clamp01(float64(y)/float64(b.Height)*1.6))
			for x := 0; x < b.Width; x++ {
				i := u.setBg.PixOffset(x, y)
				u.setBg.Pix[i], u.setBg.Pix[i+1], u.setBg.Pix[i+2], u.setBg.Pix[i+3] = col.r, col.g, col.b, 255
			}
		}
	}
	copy(img.Pix, u.setBg.Pix)
	rad := 12 * s
	var cardTop int
	for i, it := range u.setItems {
		r := shift(it.r, sc)
		switch it.kind {
		case kStatus:
			roundRectGrad(img, r, rad, cDeep, cBgGrad, cLine)
		case kRow:
			if it.first {
				cardTop = r.Y
			}
			if it.last {
				roundRect(img, walk.Rectangle{X: r.X, Y: cardTop, Width: r.Width, Height: r.Y + r.Height - cardTop}, rad, cCard, cLine)
			}
		case kNative:
			roundRect(img, r, 10*s, cCard, cLine)
		case kButtons:
			for _, bt := range it.btns {
				br := shift(bt.r, sc)
				if bt.primary {
					roundRectGrad(img, br, float64(br.Height)/2, cRoyal, cDeep, cSky)
				} else {
					roundRect(img, br, float64(br.Height)/2, cBg, cGold)
				}
			}
		}
		_ = i
	}
	// подсветка строки под курсором и переключатели
	for i, it := range u.setItems {
		if it.kind != kRow {
			continue
		}
		r := shift(it.r, sc)
		if i == u.setHover && it.act != nil {
			hr := walk.Rectangle{X: r.X + 1, Y: r.Y + 1, Width: r.Width - 2, Height: r.Height - 2}
			rr := 3 * s
			if it.first || it.last {
				rr = rad - 1
			}
			roundRect(img, hr, rr, cCardHover, cCardHover)
		}
		if it.toggle {
			tw, th := int(42*s), int(24*s)
			tr := walk.Rectangle{X: r.X + r.Width - tw - int(14*s), Y: r.Y + (r.Height-th)/2, Width: tw, Height: th}
			if it.on {
				roundRectGrad(img, tr, float64(th)/2, cSky, cRoyal, cSky)
				circleShape(img, walk.Rectangle{X: tr.X + tw - th + int(3*s), Y: tr.Y + int(3*s), Width: th - int(6*s), Height: th - int(6*s)}, cWhite, cWhite)
			} else {
				roundRect(img, tr, float64(th)/2, cDarkGray, cLine)
				circleShape(img, walk.Rectangle{X: tr.X + int(3*s), Y: tr.Y + int(3*s), Width: th - int(6*s), Height: th - int(6*s)}, cSteel, cSteel)
			}
		}
	}
	// разделители строк, полоса прокрутки и подложка сообщения — тоже в картинку
	for _, it := range u.setItems {
		if it.kind == kRow && !it.last {
			r := shift(it.r, sc)
			x := r.X + int(16*s)
			fillRectImg(img, walk.Rectangle{X: x, Y: r.Y + r.Height - 1, Width: r.X + r.Width - x - int(1*s), Height: 1}, cLine)
		}
	}
	if u.contentH > b.Height {
		trackH := b.Height - int(16*s)
		barH := int(math.Max(float64(trackH)*float64(b.Height)/float64(u.contentH), 30*s))
		maxScroll := u.contentH - b.Height
		barY := int(8*s) + int(float64(trackH-barH)*float64(sc)/float64(maxScroll))
		roundRect(img, walk.Rectangle{X: b.Width - int(7*s), Y: barY, Width: int(4 * s), Height: barH}, 2*s, cSteel, cSteel)
	}
	var toastR walk.Rectangle
	toastF := u.txt.font("Segoe UI Semibold", int(13*s), false)
	showToast := u.toast != "" && time.Since(u.toastAt) < 2*time.Second
	if showToast {
		tw, th := u.txt.measure(o.dc, u.toast, toastF)
		toastR = walk.Rectangle{X: (b.Width - tw - int(36*s)) / 2, Y: b.Height - th - int(40*s), Width: tw + int(36*s), Height: th + int(16*s)}
		roundRect(img, toastR, float64(toastR.Height)/2, cGold, cGold)
	}
	o.upload()

	hdc := o.dc
	fT, fS, fV, fSec, fB := u.fonts()
	for _, it := range u.setItems {
		r := shift(it.r, sc)
		switch it.kind {
		case kStatus:
			fs := u.txt.font("Segoe UI", int(13*s), false)
			y := r.Y + int(10*s)
			for i, l := range it.lines {
				col, f := cLight, fs
				if i == 0 {
					col, f = cGoldLight, u.txt.font("Segoe UI Semibold", int(13*s), false)
				}
				h := u.textHeight(l, f, r.Width-int(28*s))
				u.txt.draw(hdc, l, f, col, walk.Rectangle{X: r.X + int(14*s), Y: y, Width: r.Width - int(28*s), Height: h}, dtWord)
				y += h + int(2*s)
			}
			for _, l := range it.warns {
				h := u.textHeight(l, fs, r.Width-int(28*s))
				u.txt.draw(hdc, l, fs, cGold, walk.Rectangle{X: r.X + int(14*s), Y: y, Width: r.Width - int(28*s), Height: h}, dtWord)
				y += h + int(2*s)
			}
		case kSection:
			u.txt.draw(hdc, it.title, fSec, cGold, r, dtLeft|dtVCenter|dtSingle)
		case kText:
			u.txt.draw(hdc, it.title, u.txt.font("Segoe UI", int(13*s), false), cSteel, r, dtWord)
		case kButtons:
			for _, bt := range it.btns {
				col := cWhite
				if !bt.primary {
					col = cGoldLight
				}
				u.txt.draw(hdc, bt.label, fB, col, shift(bt.r, sc), dtCenter|dtVCenter|dtSingle)
			}
		case kRow:
			x := r.X + int(16*s)
			right := r.X + r.Width - int(16*s)
			switch {
			case it.toggle:
				right -= int(50 * s)
			case it.nav:
				u.txt.draw(hdc, "›", u.txt.font("Segoe UI", int(22*s), false), cSteel,
					walk.Rectangle{X: right - int(10*s), Y: r.Y, Width: int(14 * s), Height: r.Height}, dtCenter|dtVCenter|dtSingle)
				right -= int(20 * s)
			case it.radio && it.selected:
				u.txt.draw(hdc, "✓", u.txt.font("Segoe UI Symbol", int(17*s), false), cGold,
					walk.Rectangle{X: right - int(20*s), Y: r.Y, Width: int(20 * s), Height: r.Height}, dtCenter|dtVCenter|dtSingle)
				right -= int(28 * s)
			}
			if it.value != "" {
				vw, _ := u.txt.measure(hdc, it.value, fV)
				if vw > r.Width/2 {
					vw = r.Width / 2
				}
				u.txt.draw(hdc, it.value, fV, cSteel, walk.Rectangle{X: right - vw, Y: r.Y, Width: vw, Height: r.Height}, dtRight|dtVCenter|dtSingle|0x8000 /*END_ELLIPSIS*/)
				right -= vw + int(10*s)
			}
			tcol := cText
			if it.danger {
				tcol = cDanger
			} else if it.radio && it.selected {
				tcol = cGoldLight
			}
			if it.sub == "" {
				u.txt.draw(hdc, it.title, fT, tcol, walk.Rectangle{X: x, Y: r.Y, Width: right - x, Height: r.Height}, dtLeft|dtVCenter|dtSingle|0x8000)
			} else {
				ty := r.Y + int(10*s)
				u.txt.draw(hdc, it.title, fT, tcol, walk.Rectangle{X: x, Y: ty, Width: right - x, Height: int(20 * s)}, dtLeft|dtSingle|0x8000)
				u.txt.draw(hdc, it.sub, fS, cSteel, walk.Rectangle{X: x, Y: ty + int(22*s), Width: right - x, Height: r.Height - int(36*s)}, dtWord)
			}
		}
	}
	if showToast {
		u.txt.draw(hdc, u.toast, toastF, cBg, toastR, dtCenter|dtVCenter|dtSingle)
	}
}

// ---------------------------------------------------------------------------
// Мышь

func (u *nativeUI) hitSetting(x, y int) (int, *sBtn) {
	y += u.scroll
	for i, it := range u.setItems {
		switch it.kind {
		case kRow:
			if it.act != nil && inRect(it.r, x, y) {
				return i, nil
			}
		case kButtons:
			for _, bt := range it.btns {
				if inRect(bt.r, x, y) {
					return i, bt
				}
			}
		}
	}
	return -1, nil
}

func (u *nativeUI) settingsDown(x, y int, button walk.MouseButton) {
	if button != walk.LeftButton {
		return
	}
	_ = u.setPane.SetFocus()
	i, bt := u.hitSetting(x, y)
	switch {
	case bt != nil && bt.act != nil:
		bt.act()
	case i >= 0 && u.setItems[i].act != nil:
		u.setItems[i].act()
	}
	u.setPane.Invalidate()
}

func (u *nativeUI) settingsMove(x, y int, _ walk.MouseButton) {
	// Колёсико мыши в Windows 7 приходит окну с фокусом: забираем фокус, когда курсор над
	// страницей (если только пользователь не печатает в поле ввода).
	if f := win.GetFocus(); f != u.setPane.Handle() {
		typing := false
		for _, n := range u.allNatives() {
			if n.Handle() == f {
				typing = true
			}
		}
		if !typing {
			win.SetFocus(u.setPane.Handle())
		}
	}
	if u.hover != 0 {
		u.hover = 0
		u.title.Invalidate()
	}
	i, bt := u.hitSetting(x, y)
	if bt != nil || i >= 0 {
		u.setPane.SetCursor(walk.CursorHand())
	} else {
		u.setPane.SetCursor(walk.CursorArrow())
	}
	if bt != nil {
		i = -1
	}
	if i != u.setHover {
		u.setHover = i
		u.setPane.Invalidate()
	}
}
