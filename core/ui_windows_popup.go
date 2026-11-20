//go:build windows

package main

// Всплывающие окна в стиле программы: меню значка в трее и вопрос при закрытии окна.
// Стандартное меню Windows нельзя перекрасить, поэтому это отдельное маленькое окно,
// которое программа рисует сама (как и всё остальное окно): тёмная карточка,
// золотой заголовок, подсветка пункта под курсором.

import (
	"syscall"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
)

type popItem struct {
	label            string
	sep              bool // разделитель
	primary, danger  bool // кнопка (диалог) / красный пункт
	check, checked   bool // флажок «Запомнить выбор»
	disabled         bool // недоступный пункт (серый)
	button           bool // кнопка внизу диалога (а не строка меню)
	act              func()
	r                walk.Rectangle
	keepOpenOnAction bool
}

type popup struct {
	u      *nativeUI
	hwnd   win.HWND
	dialog bool   // диалог (по центру окна, окно программы недоступно) или меню
	down   bool   // меню раскрывается вниз от курсора (контекстное меню), иначе — вверх (трей)
	header bool   // шапка с логотипом (меню трея)
	title  string // заголовок диалога
	text   string // текст диалога
	items  []*popItem
	hover  int
	w, h   int
	off    offscreen
	onEsc  func()
}

var (
	curPopup     *popup
	popupClass   *uint16
	popupWndProc uintptr

	user32            = syscall.NewLazyDLL("user32.dll")
	gdi32             = syscall.NewLazyDLL("gdi32.dll")
	procMonFromPoint  = user32.NewProc("MonitorFromPoint")
	procSetWindowRgn  = user32.NewProc("SetWindowRgn")
	procRoundRectRgn  = gdi32.NewProc("CreateRoundRectRgn")
	procGetWindowRect = user32.NewProc("GetWindowRect")
)

func registerPopupClass() bool {
	if popupClass != nil {
		return true
	}
	name, _ := syscall.UTF16PtrFromString("AristocratNETPopup")
	popupWndProc = syscall.NewCallback(popupProc)
	wc := win.WNDCLASSEX{
		Style:         win.CS_DROPSHADOW,
		LpfnWndProc:   popupWndProc,
		HInstance:     win.GetModuleHandle(nil),
		HCursor:       win.LoadCursor(0, win.MAKEINTRESOURCE(win.IDC_ARROW)),
		LpszClassName: name,
	}
	wc.CbSize = uint32(unsafe.Sizeof(wc))
	if win.RegisterClassEx(&wc) == 0 {
		return false
	}
	popupClass = name
	return true
}

func popupProc(hwnd win.HWND, msg uint32, wp, lp uintptr) uintptr {
	p := curPopup
	if p == nil || p.hwnd != hwnd {
		return win.DefWindowProc(hwnd, msg, wp, lp)
	}
	switch msg {
	case win.WM_ERASEBKGND:
		return 1
	case win.WM_PAINT:
		var ps win.PAINTSTRUCT
		hdc := win.BeginPaint(hwnd, &ps)
		p.paint(hdc)
		win.EndPaint(hwnd, &ps)
		return 0
	case win.WM_MOUSEMOVE:
		x, y := int(int16(lp&0xffff)), int(int16((lp>>16)&0xffff))
		if i := p.hit(x, y); i != p.hover {
			p.hover = i
			win.InvalidateRect(hwnd, nil, false)
		}
		tme := win.TRACKMOUSEEVENT{DwFlags: win.TME_LEAVE, HwndTrack: hwnd}
		tme.CbSize = uint32(unsafe.Sizeof(tme))
		win.TrackMouseEvent(&tme)
		return 0
	case win.WM_MOUSELEAVE:
		if p.hover != -1 {
			p.hover = -1
			win.InvalidateRect(hwnd, nil, false)
		}
		return 0
	case win.WM_LBUTTONUP:
		x, y := int(int16(lp&0xffff)), int(int16((lp>>16)&0xffff))
		if i := p.hit(x, y); i >= 0 {
			it := p.items[i]
			if it.check && it.act == nil { // флажок в диалоге: только отметить
				it.checked = !it.checked
				win.InvalidateRect(hwnd, nil, false)
				return 0
			}
			p.close()
			if it.act != nil {
				it.act()
			}
		}
		return 0
	case win.WM_KEYDOWN:
		if wp == win.VK_ESCAPE {
			p.close()
			if p.onEsc != nil {
				p.onEsc()
			}
		}
		return 0
	case win.WM_ACTIVATE:
		if wp&0xffff == win.WA_INACTIVE && !p.dialog {
			// меню закрывается, как обычное, при щелчке мимо него
			p.u.mw.Synchronize(p.close)
		}
		return 0
	}
	return win.DefWindowProc(hwnd, msg, wp, lp)
}

func (p *popup) hit(x, y int) int {
	for i, it := range p.items {
		if !it.sep && !it.disabled && inRect(it.r, x, y) {
			return i
		}
	}
	return -1
}

func (p *popup) close() {
	if curPopup != p || p.hwnd == 0 {
		return
	}
	h := p.hwnd
	p.hwnd = 0
	curPopup = nil
	if p.dialog {
		win.EnableWindow(p.u.mw.Handle(), true)
		win.SetForegroundWindow(p.u.mw.Handle())
	}
	win.DestroyWindow(h)
	p.off.free()
}

// layout расставляет пункты и возвращает размер окна.
func (p *popup) layout() {
	s := p.u.dpiScale()
	pad := int(10 * s)
	w := int(250 * s)
	if p.dialog {
		w = int(340 * s)
	}
	y := pad
	hdc := win.GetDC(0)
	defer win.ReleaseDC(0, hdc)
	if p.dialog {
		y += int(8 * s)
		tf := p.u.txt.font("Segoe UI Semibold", int(17*s), false)
		_, th := p.u.txt.measure(hdc, p.title, tf)
		y += th + int(8*s)
		if p.text != "" {
			y += p.u.textHeight(p.text, p.u.txt.font("Segoe UI", int(13*s), false), w-2*pad-int(12*s)) + int(12*s)
		}
	} else if p.header {
		y += int(34 * s) // шапка: логотип и название
	}
	var btns []*popItem
	for _, it := range p.items {
		switch {
		case it.button:
			btns = append(btns, it)
		case it.sep:
			it.r = walk.Rectangle{X: pad, Y: y + int(4*s), Width: w - 2*pad, Height: 1}
			y += int(9 * s)
		default:
			it.r = walk.Rectangle{X: pad / 2, Y: y, Width: w - pad, Height: int(36 * s)}
			y += int(36 * s)
		}
	}
	if len(btns) > 0 {
		y += int(8 * s)
		bf := p.u.txt.font("Segoe UI Semibold", int(13*s), false)
		x := w - pad
		for i := len(btns) - 1; i >= 0; i-- {
			tw, _ := p.u.txt.measure(hdc, btns[i].label, bf)
			bw := tw + int(36*s)
			x -= bw
			btns[i].r = walk.Rectangle{X: x, Y: y, Width: bw, Height: int(38 * s)}
			x -= int(10 * s)
		}
		y += int(38 * s)
	}
	p.w, p.h = w, y+pad+int(4*s)
}

func (p *popup) paint(hdc win.HDC) {
	if !p.off.ensure(p.w, p.h) {
		return
	}
	s := p.u.dpiScale()
	o := &p.off
	img := o.img
	b := walk.Rectangle{Width: p.w, Height: p.h}
	fillRectImg(img, b, cBg)
	roundRectGrad(img, walk.Rectangle{X: 0, Y: 0, Width: p.w, Height: p.h}, 12*s, cCard, cBg, cLine)
	for i, it := range p.items {
		switch {
		case it.sep:
			fillRectImg(img, it.r, cLine)
		case it.button && it.primary:
			c1, c2 := cSky, cRoyal
			if i == p.hover {
				c1, c2 = cLight, cSky
			}
			roundRectGrad(img, it.r, float64(it.r.Height)/2, c1, c2, c1)
		case it.button:
			fill := cBg
			if i == p.hover {
				fill = cCardHover
			}
			roundRect(img, it.r, float64(it.r.Height)/2, fill, cGold)
		case i == p.hover:
			roundRect(img, it.r, 8*s, cCardHover, cCardHover)
		}
		if it.check {
			box := walk.Rectangle{X: it.r.X + int(10*s), Y: it.r.Y + (it.r.Height-int(18*s))/2, Width: int(18 * s), Height: int(18 * s)}
			if it.checked {
				roundRectGrad(img, box, 4*s, cSky, cRoyal, cSky)
			} else {
				roundRect(img, box, 4*s, cDarkGray, cSteel)
			}
		}
	}
	if p.header && p.u.logoImg != nil {
		lr := walk.Rectangle{X: int(14 * s), Y: int(12 * s), Width: int(24 * s), Height: int(24 * s)}
		drawImageScaled(img, p.u.logoImg, lr)
	}
	o.upload()

	// текст поверх картинки
	pad := int(10 * s)
	t := p.u.txt
	if p.dialog {
		tf := t.font("Segoe UI Semibold", int(17*s), false)
		_, th := t.measure(o.dc, p.title, tf)
		y := pad + int(8*s)
		t.draw(o.dc, p.title, tf, cGoldLight, walk.Rectangle{X: pad + int(6*s), Y: y, Width: p.w - 2*pad, Height: th}, dtLeft|dtSingle)
		y += th + int(8*s)
		if p.text != "" {
			f := t.font("Segoe UI", int(13*s), false)
			hh := p.u.textHeight(p.text, f, p.w-2*pad-int(12*s))
			t.draw(o.dc, p.text, f, cText, walk.Rectangle{X: pad + int(6*s), Y: y, Width: p.w - 2*pad - int(12*s), Height: hh}, dtWord)
		}
	} else if p.header {
		f := t.font("Segoe UI Semibold", int(14*s), false)
		r := walk.Rectangle{X: int(46 * s), Y: int(10 * s), Width: p.w, Height: int(28 * s)}
		w1, _ := t.measure(o.dc, "Aristocrat ", f)
		t.draw(o.dc, "Aristocrat ", f, cGold, r, dtLeft|dtVCenter|dtSingle)
		r.X += w1
		t.draw(o.dc, "NET", f, cLight, r, dtLeft|dtVCenter|dtSingle)
	}
	for _, it := range p.items {
		if it.sep {
			continue
		}
		switch {
		case it.button:
			col := cGoldLight
			if it.primary {
				col = cWhite
			}
			t.draw(o.dc, it.label, t.font("Segoe UI Semibold", int(13*s), false), col, it.r, dtCenter|dtVCenter|dtSingle)
		default:
			col := cText
			if it.danger {
				col = cDanger
			}
			if it.disabled {
				col = cSteel
			}
			r := it.r
			r.X += int(14 * s)
			if it.check {
				r.X += int(26 * s)
			}
			r.Width -= int(20 * s)
			t.draw(o.dc, it.label, t.font("Segoe UI", int(14*s), false), col, r, dtLeft|dtVCenter|dtSingle)
		}
	}
	win.BitBlt(hdc, 0, 0, int32(p.w), int32(p.h), o.dc, 0, 0, win.SRCCOPY)
}

// show создаёт окно. Для меню (x, y) — точка курсора, для диалога — по центру окна программы.
func (p *popup) show(x, y int) {
	if curPopup != nil {
		curPopup.close()
	}
	if !registerPopupClass() {
		return
	}
	p.hover = -1
	p.layout()
	s := p.u.dpiScale()

	// Рабочая область монитора (без панели задач).
	var mi win.MONITORINFO
	mi.CbSize = uint32(unsafe.Sizeof(mi))
	// POINT передаётся по значению: на 64 битах — одним числом, на 32 — двумя.
	pt := uint64(uint32(int32(x))) | uint64(uint32(int32(y)))<<32
	var mon uintptr
	if unsafe.Sizeof(uintptr(0)) == 8 {
		mon, _, _ = procMonFromPoint.Call(uintptr(pt), win.MONITOR_DEFAULTTONEAREST)
	} else {
		mon, _, _ = procMonFromPoint.Call(uintptr(uint32(int32(x))), uintptr(uint32(int32(y))), win.MONITOR_DEFAULTTONEAREST)
	}
	work := win.RECT{Right: 1920, Bottom: 1080}
	if mon != 0 && win.GetMonitorInfo(win.HMONITOR(mon), &mi) {
		work = mi.RcWork
	}

	if p.dialog {
		var r win.RECT
		procGetWindowRect.Call(uintptr(p.u.mw.Handle()), uintptr(unsafe.Pointer(&r)))
		x = int(r.Left+r.Right)/2 - p.w/2
		y = int(r.Top+r.Bottom)/2 - p.h/2
	} else if p.down {
		// контекстное меню — вниз и вправо от курсора; у края экрана — в другую сторону
		if x+p.w > int(work.Right) {
			x -= p.w
		}
		if y+p.h > int(work.Bottom) {
			y -= p.h
		}
	} else {
		// меню трея — над курсором (панель задач обычно внизу), не выходя за экран
		x -= p.w - int(8*s)
		y -= p.h
	}
	if x+p.w > int(work.Right) {
		x = int(work.Right) - p.w
	}
	if y+p.h > int(work.Bottom) {
		y = int(work.Bottom) - p.h
	}
	if x < int(work.Left) {
		x = int(work.Left)
	}
	if y < int(work.Top) {
		y = int(work.Top)
	}

	var owner win.HWND
	if p.dialog {
		owner = p.u.mw.Handle()
	}
	curPopup = p
	h := win.CreateWindowEx(win.WS_EX_TOPMOST|win.WS_EX_TOOLWINDOW, popupClass, nil, win.WS_POPUP,
		int32(x), int32(y), int32(p.w), int32(p.h), owner, 0, win.GetModuleHandle(nil), nil)
	if h == 0 {
		curPopup = nil
		return
	}
	p.hwnd = h
	rad := int(24 * s)
	if rgn, _, _ := procRoundRectRgn.Call(0, 0, uintptr(p.w+1), uintptr(p.h+1), uintptr(rad), uintptr(rad)); rgn != 0 {
		procSetWindowRgn.Call(uintptr(h), rgn, 1)
	}
	if p.dialog {
		win.EnableWindow(p.u.mw.Handle(), false)
	}
	win.ShowWindow(h, win.SW_SHOW)
	win.SetForegroundWindow(h)
	win.SetFocus(h)
}

// ---------------------------------------------------------------------------

// trayMenu — меню по правой кнопке на значке в трее.
func (u *nativeUI) trayMenu() {
	var pt win.POINT
	win.GetCursorPos(&pt)
	toggle := "Включить обход"
	if u.a.eng.Running() {
		toggle = "Выключить обход"
	}
	p := &popup{u: u, header: true, items: []*popItem{
		{label: "Открыть " + appTitle, act: u.showWindow},
		{label: toggle, act: u.toggle},
	}}
	shareOn, _ := u.a.shareOn()
	recvOn, _, _ := u.a.recvOn()
	p.items = append(p.items,
		// В трее — без вопросов: с обходом, если обход включён.
		&popItem{label: "Раздать интернет", check: true, checked: shareOn, act: func() { u.lanShare(!shareOn, u.a.eng.Running()) }},
		&popItem{label: "Интернет с телефона", check: true, checked: recvOn, act: u.recvClick},
	)
	if u.showAnt() { // сборка разработчика: переключатель раздачи «Ебаная Чукотка»
		p.items = append(p.items, &popItem{label: "Раздача «Ебаная Чукотка»", check: true, checked: u.a.dev.On(), act: u.toggleShare})
	}
	p.items = append(p.items, []*popItem{
		{sep: true},
		{label: "Настройки", act: func() { u.showWindow(); u.setView(viewSettings) }},
		{label: "Выход", danger: true, act: func() { go u.quit() }},
	}...)
	p.show(int(pt.X), int(pt.Y))
}

// askClose — нажали ✕ (или Alt+F4): спросить, свернуть в трей или выйти.
func (u *nativeUI) askClose() {
	switch u.a.settings().CloseAction {
	case "tray":
		u.hideToTray()
		return
	case "quit":
		go u.quit()
		return
	}
	remember := &popItem{label: "Запомнить выбор", check: true}
	p := &popup{u: u, dialog: true, title: "Закрыть " + appTitle + "?",
		text: "В трее программа продолжит работать, и защита останется включённой. «Выйти» — выключить защиту и закрыть программу."}
	save := func(action string) {
		if remember.checked {
			u.apply(func(s *Settings) { s.CloseAction = action })
		}
	}
	p.items = []*popItem{
		remember,
		{label: "Выйти", button: true, act: func() { save("quit"); go u.quit() }},
		{label: "Свернуть в трей", button: true, primary: true, act: func() { save("tray"); u.hideToTray() }},
	}
	p.show(0, 0)
}

// ---------------------------------------------------------------------------
// Контекстное меню полей ввода (вместо системного «Отменить / Вырезать / Копировать…»).

var (
	editOldProc = map[win.HWND]uintptr{}
	editProc    uintptr
	activeUI    *nativeUI
)

// styleEditMenu подменяет обработчик окна поля ввода: правая кнопка — своё меню.
func (u *nativeUI) styleEditMenu(h win.HWND) {
	activeUI = u
	if editProc == 0 {
		editProc = syscall.NewCallback(editSubProc)
	}
	if _, ok := editOldProc[h]; ok {
		return
	}
	editOldProc[h] = win.SetWindowLongPtr(h, win.GWLP_WNDPROC, editProc)
}

func editSubProc(hwnd win.HWND, msg uint32, wp, lp uintptr) uintptr {
	if msg == win.WM_CONTEXTMENU && activeUI != nil {
		x, y := int(int16(lp&0xffff)), int(int16((lp>>16)&0xffff))
		if x == -1 && y == -1 { // с клавиатуры — у курсора мыши
			var pt win.POINT
			win.GetCursorPos(&pt)
			x, y = int(pt.X), int(pt.Y)
		}
		activeUI.editMenu(hwnd, x, y)
		return 0
	}
	return win.CallWindowProc(editOldProc[hwnd], hwnd, msg, wp, lp)
}

func (u *nativeUI) editMenu(h win.HWND, x, y int) {
	win.SetFocus(h)
	ro := win.GetWindowLong(h, win.GWL_STYLE)&win.ES_READONLY != 0
	var from, to uint32
	win.SendMessage(h, win.EM_GETSEL, uintptr(unsafe.Pointer(&from)), uintptr(unsafe.Pointer(&to)))
	sel := to > from
	empty := win.SendMessage(h, win.WM_GETTEXTLENGTH, 0, 0) == 0
	canUndo := win.SendMessage(h, win.EM_CANUNDO, 0, 0) != 0
	send := func(m uint32, wp, lp uintptr) func() {
		return func() {
			win.SetForegroundWindow(u.mw.Handle())
			win.SetFocus(h)
			win.SendMessage(h, m, wp, lp)
		}
	}
	var items []*popItem
	if !ro {
		items = append(items, &popItem{label: "Отменить", disabled: !canUndo, act: send(win.EM_UNDO, 0, 0)}, &popItem{sep: true},
			&popItem{label: "Вырезать", disabled: !sel, act: send(win.WM_CUT, 0, 0)})
	}
	items = append(items, &popItem{label: "Копировать", disabled: !sel, act: send(win.WM_COPY, 0, 0)})
	if !ro {
		items = append(items,
			&popItem{label: "Вставить", act: send(win.WM_PASTE, 0, 0)},
			&popItem{label: "Удалить", disabled: !sel, act: send(win.WM_CLEAR, 0, 0)})
	}
	items = append(items, &popItem{sep: true}, &popItem{label: "Выделить всё", disabled: empty, act: send(win.EM_SETSEL, 0, ^uintptr(0))})
	p := &popup{u: u, down: true, items: items}
	p.show(x, y)
}
