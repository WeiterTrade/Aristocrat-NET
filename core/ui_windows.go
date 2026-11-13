//go:build windows

package main

// Нативный интерфейс Windows 7–11 (Win32, библиотека walk; без браузера и WebView2).
//
// Одно окно без системной рамки, со своим заголовком («Земля и голубь»):
//   • главный экран — кнопка-глобус, состояние, флаг страны и IP; «О программе» справа сверху,
//     шестерёнка настроек слева снизу;
//   • настройки и «О программе» открываются в этом же окне (стрелка «назад» в заголовке).
// Окно открывается по центру экрана, перетаскивается за заголовок, вручную не растягивается,
// разворачивается на весь экран кнопкой. Закрытие сворачивает «Обход» в трей.

import (
	"bytes"
	_ "embed"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	_ "image/png"
	"io"
	"math"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	dcl "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
)

//go:embed ui/logo.png
var logoPNG []byte

func init() {
	// walk требует, чтобы окна создавались и обслуживались в главном системном потоке.
	runtime.LockOSThread()
}

// ---------------------------------------------------------------------------
// Палитра «Земля и небо»: глубокий синий, небесно-голубой, зелень Земли.

type rgb struct{ r, g, b uint8 }

var (
	cNavy      = rgb{0x0E, 0x2D, 0x4A} // заголовок, рамка
	cNavyHover = rgb{0x1D, 0x46, 0x6E}
	cCloseHov  = rgb{0xC4, 0x2B, 0x1C}
	cBgTop     = rgb{0xE6, 0xF0, 0xF7} // небо
	cBgBottom  = rgb{0xF8, 0xFB, 0xFD}
	cText      = rgb{0x14, 0x27, 0x3A}
	cMuted     = rgb{0x5E, 0x72, 0x86}
	cLink      = rgb{0x1F, 0x5F, 0x99}
	cWarn      = rgb{0xB4, 0x3C, 0x0C}
	cOk        = rgb{0x15, 0x8A, 0x63}
	cWhite     = rgb{0xFF, 0xFF, 0xFF}
	cPillLine  = rgb{0xD3, 0xDF, 0xE9}
	// небо с лучами (центр → край)
	cSkyCenter = rgb{0x7C, 0xCF, 0xF4}
	cSkyEdge   = rgb{0x12, 0x5A, 0xA8}
	cOnSky     = rgb{0xFF, 0xFF, 0xFF} // основной текст на небе
	cOnSkySub  = rgb{0xDD, 0xEE, 0xFB} // второстепенный текст на небе
	cOnSkyWarn = rgb{0xFF, 0xE0, 0xB8} // предупреждения на небе
	cOnSkyOk   = rgb{0xC8, 0xFF, 0xD8}
)

func (c rgb) walk() walk.Color        { return walk.RGB(c.r, c.g, c.b) }
func (c rgb) ref() win.COLORREF       { return win.COLORREF(uint32(c.r) | uint32(c.g)<<8 | uint32(c.b)<<16) }
func (c rgb) rgba(a uint8) color.RGBA { return color.RGBA{c.r, c.g, c.b, a} }

func lerp(a, b rgb, t float64) rgb {
	t = clamp01(t)
	f := func(x, y uint8) uint8 { return uint8(float64(x) + (float64(y)-float64(x))*t + 0.5) }
	return rgb{f(a.r, b.r), f(a.g, b.g), f(a.b, b.b)}
}

func clamp01(v float64) float64 { return math.Max(0, math.Min(1, v)) }

// ---------------------------------------------------------------------------
// Текст через GDI: шрифты ClearType и точное измерение ширины.

type fontKey struct {
	face string
	px   int
	bold bool
}

type gdiText struct{ fonts map[fontKey]win.HFONT }

func (g *gdiText) font(face string, px int, bold bool) win.HFONT {
	k := fontKey{face, px, bold}
	if f, ok := g.fonts[k]; ok {
		return f
	}
	lf := win.LOGFONT{LfHeight: -int32(px), LfWeight: 400, LfCharSet: win.DEFAULT_CHARSET, LfQuality: win.CLEARTYPE_QUALITY}
	if bold {
		lf.LfWeight = 600
	}
	name, _ := syscall.UTF16FromString(face)
	copy(lf.LfFaceName[:len(lf.LfFaceName)-1], name)
	f := win.CreateFontIndirect(&lf)
	g.fonts[k] = f
	return f
}

const (
	dtLeft     = 0x0
	dtCenter   = 0x1
	dtRight    = 0x2
	dtVCenter  = 0x4
	dtWord     = 0x10
	dtSingle   = 0x20
	dtNoPrefix = 0x800
)

func (g *gdiText) draw(hdc win.HDC, text string, f win.HFONT, c rgb, r walk.Rectangle, flags uint32) {
	u, _ := syscall.UTF16FromString(text)
	old := win.SelectObject(hdc, win.HGDIOBJ(f))
	win.SetBkMode(hdc, win.TRANSPARENT)
	win.SetTextColor(hdc, c.ref())
	rc := win.RECT{Left: int32(r.X), Top: int32(r.Y), Right: int32(r.X + r.Width), Bottom: int32(r.Y + r.Height)}
	win.DrawTextEx(hdc, &u[0], int32(len(u)-1), &rc, flags|dtNoPrefix, nil)
	win.SelectObject(hdc, old)
}

func (g *gdiText) measure(hdc win.HDC, text string, f win.HFONT) (int, int) {
	u, _ := syscall.UTF16FromString(text)
	old := win.SelectObject(hdc, win.HGDIOBJ(f))
	var sz win.SIZE
	win.GetTextExtentPoint32(hdc, &u[0], int32(len(u)-1), &sz)
	win.SelectObject(hdc, old)
	return int(sz.CX), int(sz.CY)
}

// ---------------------------------------------------------------------------
// Сглаженная графика (фон, кнопка-глобус, плашка IP, кнопка настроек).

type sceneKey struct {
	w, h       int
	state      string
	view       string
	pill, gear walk.Rectangle
	btn        walk.Rectangle
	logo       walk.Rectangle
}

func fillPx(img *image.RGBA, x, y int, c rgb, a float64) {
	if a <= 0 {
		return
	}
	i := img.PixOffset(x, y)
	p := img.Pix[i : i+3 : i+3]
	p[0] = uint8(float64(p[0]) + (float64(c.r)-float64(p[0]))*a + 0.5)
	p[1] = uint8(float64(p[1]) + (float64(c.g)-float64(p[1]))*a + 0.5)
	p[2] = uint8(float64(p[2]) + (float64(c.b)-float64(p[2]))*a + 0.5)
}

// Шум для материков (детерминированный, как в эмблеме).
func hash2(x, y int) float64 {
	h := uint32(x)*374761393 + uint32(y)*668265263 + 1442695041
	h = (h ^ (h >> 13)) * 1274126177
	h ^= h >> 16
	return float64(h&0xFFFFFF) / float64(0xFFFFFF)
}

func vnoise(x, y float64) float64 {
	xi, yi := math.Floor(x), math.Floor(y)
	xf, yf := x-xi, y-yi
	u, v := xf*xf*(3-2*xf), yf*yf*(3-2*yf)
	ix, iy := int(xi), int(yi)
	a, b := hash2(ix, iy), hash2(ix+1, iy)
	c, d := hash2(ix, iy+1), hash2(ix+1, iy+1)
	return a + (b-a)*u + (c-a)*v + (a-b-c+d)*u*v
}

func fbm(x, y float64) float64 {
	sum, amp, f := 0.0, 0.5, 1.0
	for i := 0; i < 5; i++ {
		sum += amp * vnoise(x*f, y*f)
		amp *= 0.5
		f *= 2.03
	}
	return sum
}

// sky рисует фон: небо с мягкими лучами, расходящимися от (cx, cy).
func sky(img *image.RGBA, cx, cy float64) {
	b := img.Bounds()
	maxd := math.Hypot(float64(b.Dx()), float64(b.Dy())) * 0.62
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			dx, dy := float64(x)+0.5-cx, float64(y)+0.5-cy
			r := math.Hypot(dx, dy) / maxd
			col := lerp(cSkyCenter, cSkyEdge, r)
			ray := math.Pow(math.Max(0, math.Cos(math.Atan2(dy, dx)*18)), 6) * 0.11 * math.Max(0, 1-r*0.85)
			col = lerp(col, cWhite, ray)
			i := img.PixOffset(x, y)
			img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = col.r, col.g, col.b, 255
		}
	}
}

// planet рисует кнопку-планету: сияние, океан с объёмом, материки, светлая кайма.
// vivid=false — приглушённые цвета (обход выключен).
func planet(img *image.RGBA, r walk.Rectangle, halo int, vivid, busy bool) {
	cx := float64(r.X) + float64(r.Width)/2
	cy := float64(r.Y) + float64(r.Height)/2
	R := float64(r.Width)/2 - float64(halo)
	outer := R + float64(halo)
	b := img.Bounds()
	for y := int(cy - outer - 1); y <= int(cy+outer+1); y++ {
		if y < b.Min.Y || y >= b.Max.Y {
			continue
		}
		for x := int(cx - outer - 1); x <= int(cx+outer+1); x++ {
			if x < b.Min.X || x >= b.Max.X {
				continue
			}
			fx, fy := float64(x)+0.5-cx, float64(y)+0.5-cy
			d := math.Hypot(fx, fy)
			if d > R-1 && d < outer { // мягкое сияние вокруг планеты
				t := (d - R) / float64(halo)
				fillPx(img, x, y, cWhite, 0.32*math.Pow(1-clamp01(t), 2))
			}
			cov := clamp01(R - d + 0.5)
			if cov <= 0 {
				continue
			}
			nx, ny := fx/R, fy/R
			nd := math.Min(1, d/R)
			light := clamp01(0.55 - 0.45*(nx*0.6+ny*0.75) + 0.25*(1-nd*nd))
			col := rgb{uint8(40 + 70*light), uint8(120 + 80*light), uint8(190 + 55*light)}
			k := 1 / (math.Sqrt(math.Max(0.05, 1-nd*nd)) + 1.2) * 1.6
			if n := fbm(nx*k*2.0+5.3, ny*k*2.0+1.9); n > 0.45 {
				land := rgb{uint8(56 + 60*light), uint8(150 + 60*light), uint8(110 + 40*light)}
				col = lerp(col, land, math.Min(1, (n-0.45)*7*1.6))
			}
			if !vivid {
				g := (int(col.r) + int(col.g) + int(col.b)) / 3
				gray := rgb{uint8(g), uint8(g), uint8(g + (255-g)/8)}
				col = lerp(col, gray, 0.62)
			}
			if busy {
				col = lerp(col, rgb{0x3A, 0x8E, 0xD8}, 0.35)
			}
			// светлая атмосферная кайма
			rim := clamp01(1 - math.Abs(R-1.5-d)/1.5)
			col = lerp(col, cWhite, rim*0.45)
			fillPx(img, x, y, col, cov)
		}
	}
}

// scaleRGBA уменьшает картинку усреднением (результат — RGBA с предумноженной альфой).
func scaleRGBA(src image.Image, px int) *image.RGBA {
	dst := image.NewRGBA(image.Rect(0, 0, px, px))
	sb := src.Bounds()
	scale := float64(sb.Dx()) / float64(px)
	for y := 0; y < px; y++ {
		for x := 0; x < px; x++ {
			var r, g, b, a, n float64
			for sy := int(float64(y) * scale); sy < int(float64(y+1)*scale); sy++ {
				for sx := int(float64(x) * scale); sx < int(float64(x+1)*scale); sx++ {
					cr, cg, cb, ca := src.At(sb.Min.X+sx, sb.Min.Y+sy).RGBA()
					r, g, b, a, n = r+float64(cr), g+float64(cg), b+float64(cb), a+float64(ca), n+1
				}
			}
			if n == 0 {
				continue
			}
			i := dst.PixOffset(x, y)
			dst.Pix[i], dst.Pix[i+1], dst.Pix[i+2], dst.Pix[i+3] =
				uint8(r/n/257+0.5), uint8(g/n/257+0.5), uint8(b/n/257+0.5), uint8(a/n/257+0.5)
		}
	}
	return dst
}

// roundRect — сглаженный прямоугольник со скруглёнными углами и обводкой.
func roundRect(img *image.RGBA, r walk.Rectangle, rad float64, fill, stroke rgb) {
	b := img.Bounds()
	cx := float64(r.X) + float64(r.Width)/2
	cy := float64(r.Y) + float64(r.Height)/2
	hw, hh := float64(r.Width)/2, float64(r.Height)/2
	for y := r.Y - 1; y <= r.Y+r.Height; y++ {
		if y < b.Min.Y || y >= b.Max.Y {
			continue
		}
		for x := r.X - 1; x <= r.X+r.Width; x++ {
			if x < b.Min.X || x >= b.Max.X {
				continue
			}
			qx := math.Abs(float64(x)+0.5-cx) - (hw - rad)
			qy := math.Abs(float64(y)+0.5-cy) - (hh - rad)
			out := math.Hypot(math.Max(qx, 0), math.Max(qy, 0)) + math.Min(math.Max(qx, qy), 0) - rad
			if a := clamp01(0.5 - out); a > 0 {
				fillPx(img, x, y, stroke, a)
			}
			if a := clamp01(-0.5 - out); a > 0 {
				fillPx(img, x, y, fill, a)
			}
		}
	}
}

func circleShape(img *image.RGBA, r walk.Rectangle, fill, stroke rgb) {
	roundRect(img, r, float64(r.Width)/2, fill, stroke)
}

// ---------------------------------------------------------------------------

const (
	viewHome     = "home"
	viewSettings = "settings"
	viewAbout    = "about"
)

type nativeUI struct {
	a    *App
	quit func()

	mw        *walk.MainWindow
	title     *walk.CustomWidget
	home      *walk.CustomWidget
	settings  *walk.ScrollView
	ni        *walk.NotifyIcon
	toggleAct *walk.Action
	txt       gdiText

	mu       sync.Mutex
	view     string
	busy     bool
	errText  string
	ip, cc   string
	flag     image.Image
	flagCC   string
	lastSig  string
	quitting bool
	toldTray bool
	maxed    bool
	restore  win.RECT
	hover    int // кнопка заголовка под курсором: 0 — нет, 1 свернуть, 2 развернуть, 3 закрыть, 4 назад
	lastDown time.Time

	scene    *walk.Bitmap
	sceneKey sceneKey
	logoImg  image.Image
	logoBmp  map[string]*walk.Bitmap
	flagBmp  *walk.Bitmap

	// области щелчков (пиксели)
	rBtn, rGear, rAbout, rPill walk.Rectangle

	refreshSettings func()
	settingsReady   func()
}

func runDesktopUI(a *App, url string, show bool, quit func(), done <-chan struct{}) {
	u := &nativeUI{a: a, quit: quit, view: viewHome, txt: gdiText{fonts: map[fontKey]win.HFONT{}}, logoBmp: map[string]*walk.Bitmap{}}
	if img, _, err := image.Decode(bytes.NewReader(logoPNG)); err == nil {
		u.logoImg = img
	}
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
			u.ni.Dispose()
			u.mw.Close()
		})
	}()
	go u.ticker(done)
	go u.loadIP()

	u.mw.Starting().Attach(func() {
		u.applyFrame()
		u.center()
		if !show {
			u.mw.Hide()
		}
	})
	u.mw.Run()
}

func (u *nativeUI) build() error {
	icon, _ := walk.NewIconFromResourceId(1)
	settingsChildren := u.settingsWidgets()

	if err := (dcl.MainWindow{
		AssignTo:   &u.mw,
		Title:      "Обход",
		Icon:       icon,
		Size:       dcl.Size{Width: 440, Height: 660},
		Background: dcl.SolidColorBrush{Color: cNavy.walk()}, // это цвет рамки окна (1 пиксель)
		Layout:     dcl.VBox{Margins: dcl.Margins{Left: 1, Right: 1, Bottom: 1}, SpacingZero: true},
		Children: []dcl.Widget{
			dcl.CustomWidget{
				AssignTo:            &u.title,
				MinSize:             dcl.Size{Height: 40},
				MaxSize:             dcl.Size{Height: 40},
				PaintPixels:         u.paintTitle,
				InvalidatesOnResize: true,
				DoubleBuffering:     true,
				OnMouseDown:         u.titleDown,
				OnMouseMove:         u.titleMove,
			},
			dcl.CustomWidget{
				AssignTo:            &u.home,
				PaintPixels:         u.paintHome,
				InvalidatesOnResize: true,
				DoubleBuffering:     true,
				OnMouseDown:         u.homeDown,
				OnMouseMove:         u.homeMove,
				OnKeyDown: func(key walk.Key) {
					if u.view == viewHome && (key == walk.KeyReturn || key == walk.KeySpace) {
						u.toggle()
					}
					if key == walk.KeyEscape && u.view != viewHome {
						u.setView(viewHome)
					}
				},
			},
			dcl.ScrollView{
				AssignTo:        &u.settings,
				Visible:         false,
				HorizontalFixed: true,
				Background:      dcl.SolidColorBrush{Color: cBgBottom.walk()},
				Layout:          dcl.VBox{Margins: dcl.Margins{Left: 14, Top: 10, Right: 14, Bottom: 14}},
				Children:        settingsChildren,
			},
		},
	}.Create()); err != nil {
		return err
	}
	if icon != nil {
		_ = u.mw.SetIcon(icon)
	}
	u.settingsReady()

	// Закрытие окна (Alt+F4, кнопка ✕) — сворачивание в трей.
	u.mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		u.mu.Lock()
		quitting := u.quitting
		u.mu.Unlock()
		if quitting {
			return
		}
		*canceled = true
		u.hideToTray()
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
	u.toggleAct = add("Включить обход", u.toggle)
	_ = ni.ContextMenu().Actions().Add(walk.NewSeparatorAction())
	add("Настройки", func() { u.showWindow(); u.setView(viewSettings) })
	add("Выход", func() { go u.quit() })
	_ = ni.SetVisible(true)
	_ = u.home.SetFocus()
	return nil
}

// ---------------------------------------------------------------------------
// Окно: своя рамка, центр экрана, развернуть/восстановить

func (u *nativeUI) dpiScale() float64 { return float64(u.mw.DPI()) / 96 }

// applyFrame убирает системный заголовок и рамку растягивания (окно нельзя тянуть мышью).
func (u *nativeUI) applyFrame() {
	h := u.mw.Handle()
	style := win.GetWindowLong(h, win.GWL_STYLE)
	style &^= win.WS_CAPTION | win.WS_THICKFRAME
	style |= win.WS_SYSMENU | win.WS_MINIMIZEBOX | win.WS_MAXIMIZEBOX
	win.SetWindowLong(h, win.GWL_STYLE, style)
	s := u.dpiScale()
	win.SetWindowPos(h, 0, 0, 0, int32(440*s), int32(660*s), win.SWP_FRAMECHANGED|win.SWP_NOMOVE|win.SWP_NOZORDER)
}

func (u *nativeUI) workArea() win.RECT {
	mon := win.MonitorFromWindow(u.mw.Handle(), win.MONITOR_DEFAULTTONEAREST)
	mi := win.MONITORINFO{}
	mi.CbSize = uint32(unsafe.Sizeof(mi))
	if !win.GetMonitorInfo(mon, &mi) {
		return win.RECT{Right: 1280, Bottom: 720}
	}
	return mi.RcWork
}

// center ставит окно по центру экрана (каждый раз при открытии).
func (u *nativeUI) center() {
	if u.maxed {
		return
	}
	var r win.RECT
	win.GetWindowRect(u.mw.Handle(), &r)
	w, h := r.Right-r.Left, r.Bottom-r.Top
	wa := u.workArea()
	x := wa.Left + (wa.Right-wa.Left-w)/2
	y := wa.Top + (wa.Bottom-wa.Top-h)/2
	win.SetWindowPos(u.mw.Handle(), 0, x, y, 0, 0, win.SWP_NOSIZE|win.SWP_NOZORDER)
}

func (u *nativeUI) toggleMax() {
	h := u.mw.Handle()
	if u.maxed {
		r := u.restore
		win.SetWindowPos(h, 0, r.Left, r.Top, r.Right-r.Left, r.Bottom-r.Top, win.SWP_NOZORDER)
		u.maxed = false
		u.center()
	} else {
		win.GetWindowRect(h, &u.restore)
		wa := u.workArea()
		win.SetWindowPos(h, 0, wa.Left, wa.Top, wa.Right-wa.Left, wa.Bottom-wa.Top, win.SWP_NOZORDER)
		u.maxed = true
	}
	u.title.Invalidate()
}

func (u *nativeUI) showWindow() {
	wasHidden := !u.mw.Visible()
	u.mw.Show()
	if win.IsIconic(u.mw.Handle()) {
		win.ShowWindow(u.mw.Handle(), win.SW_RESTORE)
	}
	if wasHidden {
		u.center()
	}
	_ = u.mw.Activate()
	win.SetForegroundWindow(u.mw.Handle())
}

func (u *nativeUI) hideToTray() {
	u.mw.Hide()
	u.mu.Lock()
	tell := !u.toldTray
	u.toldTray = true
	u.mu.Unlock()
	if tell {
		_ = u.ni.ShowInfo("«Обход» продолжает работать", "Окно свёрнуто в трей. Щёлкните по значку, чтобы открыть его снова.")
	}
}

func (u *nativeUI) setView(v string) {
	u.view = v
	settings := v == viewSettings
	u.settings.SetVisible(settings)
	u.home.SetVisible(!settings)
	if settings && u.refreshSettings != nil {
		u.refreshSettings()
	}
	u.title.Invalidate()
	u.home.Invalidate()
	if !settings {
		_ = u.home.SetFocus()
	}
}

// ---------------------------------------------------------------------------
// Заголовок окна

func (u *nativeUI) titleButtons(w int) (min, max, cls, back walk.Rectangle) {
	s := u.dpiScale()
	bw, h := int(46*s), int(40*s)
	cls = walk.Rectangle{X: w - bw, Width: bw, Height: h}
	max = walk.Rectangle{X: w - 2*bw, Width: bw, Height: h}
	min = walk.Rectangle{X: w - 3*bw, Width: bw, Height: h}
	back = walk.Rectangle{Width: int(44 * s), Height: h}
	return
}

func (u *nativeUI) logoBitmap(px int, bg rgb) *walk.Bitmap {
	key := fmt.Sprintf("%d|%v", px, bg)
	if b, ok := u.logoBmp[key]; ok {
		return b
	}
	if u.logoImg == nil {
		return nil
	}
	dst := image.NewRGBA(image.Rect(0, 0, px, px))
	draw.Draw(dst, dst.Bounds(), &image.Uniform{bg.rgba(255)}, image.Point{}, draw.Src)
	// уменьшение с усреднением (без внешних библиотек)
	sb := u.logoImg.Bounds()
	scale := float64(sb.Dx()) / float64(px)
	for y := 0; y < px; y++ {
		for x := 0; x < px; x++ {
			var r, g, b, a float64
			n := 0.0
			for sy := int(float64(y) * scale); sy < int(float64(y+1)*scale); sy++ {
				for sx := int(float64(x) * scale); sx < int(float64(x+1)*scale); sx++ {
					cr, cg, cb, ca := u.logoImg.At(sb.Min.X+sx, sb.Min.Y+sy).RGBA()
					r, g, b, a = r+float64(cr), g+float64(cg), b+float64(cb), a+float64(ca)
					n++
				}
			}
			if n == 0 {
				continue
			}
			al := a / n / 65535
			pr, pg, pb := r/n/257, g/n/257, b/n/257 // уже умножены на альфу
			i := dst.PixOffset(x, y)
			dst.Pix[i] = uint8(pr + float64(bg.r)*(1-al) + 0.5)
			dst.Pix[i+1] = uint8(pg + float64(bg.g)*(1-al) + 0.5)
			dst.Pix[i+2] = uint8(pb + float64(bg.b)*(1-al) + 0.5)
		}
	}
	bmp, err := walk.NewBitmapFromImageForDPI(dst, 96)
	if err != nil {
		return nil
	}
	u.logoBmp[key] = bmp
	return bmp
}

func (u *nativeUI) paintTitle(c *walk.Canvas, _ walk.Rectangle) error {
	b := u.title.ClientBoundsPixels()
	s := u.dpiScale()
	hdc := c.HDC()
	brush, _ := walk.NewSolidColorBrush(cNavy.walk())
	_ = c.FillRectanglePixels(brush, b)
	brush.Dispose()
	min, max, cls, back := u.titleButtons(b.Width)

	hover := func(r walk.Rectangle, col rgb) {
		hb, _ := walk.NewSolidColorBrush(col.walk())
		_ = c.FillRectanglePixels(hb, r)
		hb.Dispose()
	}
	switch u.hover {
	case 1:
		hover(min, cNavyHover)
	case 2:
		hover(max, cNavyHover)
	case 3:
		hover(cls, cCloseHov)
	case 4:
		if u.view != viewHome {
			hover(back, cNavyHover)
		}
	}

	x := int(12 * s)
	title := "Обход"
	if u.view != viewHome {
		u.txt.draw(hdc, "←", u.txt.font("Segoe UI", int(18*s), false), cWhite, back, dtCenter|dtVCenter|dtSingle)
		x = back.Width + int(4*s)
		title = map[string]string{viewSettings: "Настройки", viewAbout: "О программе"}[u.view]
	} else {
		lp := int(22 * s)
		if bmp := u.logoBitmap(lp, cNavy); bmp != nil {
			_ = c.DrawImagePixels(bmp, walk.Point{X: x, Y: (b.Height - lp) / 2})
		}
		x += lp + int(9*s)
	}
	u.txt.draw(hdc, title, u.txt.font("Segoe UI Semibold", int(14*s), false), cWhite,
		walk.Rectangle{X: x, Y: 0, Width: min.X - x, Height: b.Height}, dtLeft|dtVCenter|dtSingle)

	// значки кнопок окна
	pen, _ := walk.NewCosmeticPen(walk.PenSolid, cWhite.walk())
	defer pen.Dispose()
	ic := int(10 * s)
	cxy := func(r walk.Rectangle) (int, int) { return r.X + r.Width/2, r.Y + r.Height/2 }
	mx, my := cxy(min)
	_ = c.DrawLinePixels(pen, walk.Point{X: mx - ic/2, Y: my}, walk.Point{X: mx + ic/2 + 1, Y: my})
	ax, ay := cxy(max)
	if u.maxed {
		o := int(2 * s)
		_ = c.DrawRectanglePixels(pen, walk.Rectangle{X: ax - ic/2 + o, Y: ay - ic/2 - o, Width: ic - o + 1, Height: ic - o + 1})
		bgb, _ := walk.NewSolidColorBrush(cNavy.walk())
		if u.hover == 2 {
			bgb.Dispose()
			bgb, _ = walk.NewSolidColorBrush(cNavyHover.walk())
		}
		_ = c.FillRectanglePixels(bgb, walk.Rectangle{X: ax - ic/2, Y: ay - ic/2, Width: ic - o + 1, Height: ic - o + 1})
		bgb.Dispose()
		_ = c.DrawRectanglePixels(pen, walk.Rectangle{X: ax - ic/2, Y: ay - ic/2, Width: ic - o + 1, Height: ic - o + 1})
	} else {
		_ = c.DrawRectanglePixels(pen, walk.Rectangle{X: ax - ic/2, Y: ay - ic/2, Width: ic + 1, Height: ic + 1})
	}
	kx, ky := cxy(cls)
	_ = c.DrawLinePixels(pen, walk.Point{X: kx - ic/2, Y: ky - ic/2}, walk.Point{X: kx + ic/2 + 1, Y: ky + ic/2 + 1})
	_ = c.DrawLinePixels(pen, walk.Point{X: kx + ic/2, Y: ky - ic/2}, walk.Point{X: kx - ic/2 - 1, Y: ky + ic/2 + 1})
	return nil
}

func (u *nativeUI) titleHit(x, y int) int {
	min, max, cls, back := u.titleButtons(u.title.ClientBoundsPixels().Width)
	switch {
	case inRect(cls, x, y):
		return 3
	case inRect(max, x, y):
		return 2
	case inRect(min, x, y):
		return 1
	case u.view != viewHome && inRect(back, x, y):
		return 4
	}
	return 0
}

func (u *nativeUI) titleMove(x, y int, _ walk.MouseButton) {
	if h := u.titleHit(x, y); h != u.hover {
		u.hover = h
		u.title.Invalidate()
	}
}

func (u *nativeUI) titleDown(x, y int, button walk.MouseButton) {
	if button != walk.LeftButton {
		return
	}
	switch u.titleHit(x, y) {
	case 1:
		win.ShowWindow(u.mw.Handle(), win.SW_MINIMIZE)
	case 2:
		u.toggleMax()
	case 3:
		u.hideToTray()
	case 4:
		u.setView(viewHome)
	default:
		// двойной щелчок по заголовку — развернуть/восстановить
		if time.Since(u.lastDown) < 400*time.Millisecond {
			u.lastDown = time.Time{}
			u.toggleMax()
			return
		}
		u.lastDown = time.Now()
		if !u.maxed {
			// перетаскивание окна за заголовок средствами Windows
			win.ReleaseCapture()
			win.SendMessage(u.mw.Handle(), win.WM_NCLBUTTONDOWN, win.HTCAPTION, 0)
		}
	}
}

// ---------------------------------------------------------------------------
// Главный экран и «О программе»

func (u *nativeUI) layout(w, h int) {
	s := u.dpiScale()
	d := int(212 * s)
	cy := int(float64(h) * 0.37)
	if cy-d/2 < int(56*s) {
		cy = int(56*s) + d/2
	}
	u.rBtn = walk.Rectangle{X: w/2 - d/2, Y: cy - d/2, Width: d, Height: d}
	g := int(48 * s)
	u.rGear = walk.Rectangle{X: int(16 * s), Y: h - g - int(16*s), Width: g, Height: g}
	u.rAbout = walk.Rectangle{X: w - int(140*s), Y: int(8 * s), Width: int(128 * s), Height: int(30 * s)}
}

func (u *nativeUI) paintHome(c *walk.Canvas, _ walk.Rectangle) error {
	b := u.home.ClientBoundsPixels()
	if b.Width <= 0 || b.Height <= 0 {
		return nil
	}
	s := u.dpiScale()
	hdc := c.HDC()
	u.layout(b.Width, b.Height)

	on := u.a.eng.Running()
	st := u.a.settings()
	ts, tp, te := u.a.tor.Status()
	stalled := u.a.tor.Stalled()
	u.mu.Lock()
	busy, errText, ip, cc := u.busy, u.errText, u.ip, u.cc
	u.mu.Unlock()

	state := "off"
	if busy {
		state = "busy"
	} else if on {
		state = "on"
	}

	// Текст плашки IP и её размер (нужны для фона).
	fIP := u.txt.font("Segoe UI", int(15*s), false)
	ipText := ip
	switch ip {
	case "":
		ipText = "IP не определён"
	case "…":
		ipText = "Определяю IP…"
	}
	tw, th := u.txt.measure(hdc, ipText, fIP)
	fw, fh, gap := 0, 0, 0
	if u.flagBmp != nil && ip != "" && ip != "…" {
		fw, fh, gap = int(24*s), int(18*s), int(10*s)
	} else if cc != "" && ip != "" && ip != "…" {
		ipText = cc + "   " + ip
		tw, th = u.txt.measure(hdc, ipText, fIP)
	}
	padX, pillH := int(18*s), int(40*s)
	pillW := padX*2 + fw + gap + tw
	stateY := u.rBtn.Y + u.rBtn.Height + int(20*s)
	pillY := stateY + int(84*s)
	u.rPill = walk.Rectangle{X: (b.Width - pillW) / 2, Y: pillY, Width: pillW, Height: pillH}

	// Фон и фигуры — одной сглаженной картинкой (пересчитывается только при изменениях).
	key := sceneKey{w: b.Width, h: b.Height, state: state, view: u.view, pill: u.rPill, gear: u.rGear, btn: u.rBtn}
	if u.scene == nil || key != u.sceneKey {
		img := image.NewRGBA(image.Rect(0, 0, b.Width, b.Height))
		if u.view == viewHome {
			sky(img, float64(u.rBtn.X+u.rBtn.Width/2), float64(u.rBtn.Y+u.rBtn.Height/2))
			planet(img, u.rBtn, int(16*s), state != "off", state == "busy")
			roundRect(img, u.rPill, float64(pillH)/2, cWhite, cPillLine)
			circleShape(img, u.rGear, cWhite, cPillLine)
		} else {
			lp := int(150 * s)
			ly := int(28 * s)
			sky(img, float64(b.Width)/2, float64(ly+lp/2))
			if u.logoImg != nil {
				logo := scaleRGBA(u.logoImg, lp)
				x0 := (b.Width - lp) / 2
				draw.Draw(img, image.Rect(x0, ly, x0+lp, ly+lp), logo, image.Point{}, draw.Over)
			}
		}
		if bmp, err := walk.NewBitmapFromImageForDPI(img, 96); err == nil {
			if u.scene != nil {
				u.scene.Dispose()
			}
			u.scene, u.sceneKey = bmp, key
		}
	}
	if u.scene != nil {
		_ = c.DrawImagePixels(u.scene, walk.Point{})
	}

	if u.view == viewAbout {
		u.paintAbout(c, hdc, b, s)
		return nil
	}

	// «О программе»
	u.txt.draw(hdc, "О программе", u.txt.font("Segoe UI", int(14*s), false), cOnSky, u.rAbout, dtRight|dtVCenter|dtSingle)

	// Надпись на кнопке
	label := "Включить"
	if busy {
		label = "…"
	} else if on {
		label = "Выключить"
	}
	fBtn := u.txt.font("Segoe UI Semibold", int(23*s), false)
	sh := u.rBtn
	sh.X, sh.Y = sh.X+int(math.Max(1, s)), sh.Y+int(math.Max(1, 2*s))
	u.txt.draw(hdc, label, fBtn, rgb{0x0B, 0x33, 0x5C}, sh, dtCenter|dtVCenter|dtSingle)
	u.txt.draw(hdc, label, fBtn, cWhite, u.rBtn, dtCenter|dtVCenter|dtSingle)

	// Состояние
	stText, stCol := "Выключено", cOnSky
	if on {
		stText, stCol = "Шифрование включено", cOnSkyOk
	}
	u.txt.draw(hdc, stText, u.txt.font("Segoe UI Semibold", int(19*s), false), stCol,
		walk.Rectangle{X: 0, Y: stateY, Width: b.Width, Height: int(28 * s)}, dtCenter|dtSingle)
	sub := "Трафик идёт как обычно"
	if on {
		sub = map[string]string{RouteAuto: "Обход блокировок, при необходимости — Tor", RouteDPI: "Обход блокировок", RouteTor: "Весь трафик через Tor"}[st.Route]
		if st.Route != RouteDPI {
			switch ts {
			case "starting":
				sub += fmt.Sprintf("\nTor подключается… %d%%", tp)
			case "ready":
				sub += "\nTor подключён"
			}
		}
	}
	u.txt.draw(hdc, sub, u.txt.font("Segoe UI", int(13*s), false), cOnSkySub,
		walk.Rectangle{X: int(20 * s), Y: stateY + int(32*s), Width: b.Width - int(40*s), Height: int(44 * s)}, dtCenter|dtWord)

	// Плашка: флаг и IP — по центру под кнопкой
	x := u.rPill.X + padX
	if fw > 0 {
		_ = c.DrawImageStretchedPixels(u.flagBmp, walk.Rectangle{X: x, Y: pillY + (pillH-fh)/2, Width: fw, Height: fh})
		x += fw + gap
	}
	u.txt.draw(hdc, ipText, fIP, cText, walk.Rectangle{X: x, Y: pillY + (pillH-th)/2, Width: tw + 2, Height: th}, dtLeft|dtSingle)

	// Ошибки и подсказки
	var msgs []string
	if errText != "" {
		msgs = append(msgs, errText)
	}
	if u.a.proxyErr != "" {
		msgs = append(msgs, u.a.proxyErr)
	}
	if on && st.Route != RouteDPI {
		if ts == "error" && te != "" {
			msgs = append(msgs, te)
		} else if stalled {
			msgs = append(msgs, StallHint)
		}
	}
	if len(msgs) > 0 {
		y := pillY + pillH + int(14*s)
		u.txt.draw(hdc, strings.Join(msgs, "\n"), u.txt.font("Segoe UI", int(12*s), false), cOnSkyWarn,
			walk.Rectangle{X: int(24 * s), Y: y, Width: b.Width - int(48*s), Height: u.rGear.Y - y - int(6*s)}, dtCenter|dtWord)
	}

	// Шестерёнка
	u.txt.draw(hdc, "⚙", u.txt.font("Segoe UI Symbol", int(23*s), false), cMuted, u.rGear, dtCenter|dtVCenter|dtSingle)
	u.txt.draw(hdc, "v"+appVersion, u.txt.font("Segoe UI", int(11*s), false), cOnSkySub,
		walk.Rectangle{X: 0, Y: u.rGear.Y, Width: b.Width - int(16*s), Height: u.rGear.Height}, dtRight|dtVCenter|dtSingle)
	return nil
}

func (u *nativeUI) paintAbout(c *walk.Canvas, hdc win.HDC, b walk.Rectangle, s float64) {
	y := int(28*s) + int(150*s) + int(10*s)
	u.txt.draw(hdc, "Обход", u.txt.font("Segoe UI Semibold", int(26*s), false), cOnSky,
		walk.Rectangle{Y: y, Width: b.Width, Height: int(34 * s)}, dtCenter|dtSingle)
	y += int(34 * s)
	u.txt.draw(hdc, "версия "+appVersion, u.txt.font("Segoe UI", int(13*s), false), cOnSkySub,
		walk.Rectangle{Y: y, Width: b.Width, Height: int(20 * s)}, dtCenter|dtSingle)
	y += int(32 * s)
	text := "Шифрует DNS и обходит блокировки провайдера прямо на компьютере — без VPN-подписок и своих серверов.\n\n" +
		"Сначала соединение идёт напрямую: начало защищённого соединения нарезается так, что фильтр провайдера (DPI) " +
		"не узнаёт сайт. Если сайт заблокирован по IP или обход не помог — соединение автоматически идёт через сеть Tor.\n\n" +
		"Используются: Tor и lyrebird (Tor Project). Лицензия MIT."
	u.txt.draw(hdc, text, u.txt.font("Segoe UI", int(13*s), false), cOnSky,
		walk.Rectangle{X: int(30 * s), Y: y, Width: b.Width - int(60*s), Height: b.Height - y - int(16*s)}, dtCenter|dtWord)
}

func inRect(r walk.Rectangle, x, y int) bool {
	return x >= r.X && y >= r.Y && x < r.X+r.Width && y < r.Y+r.Height
}

func inCircle(r walk.Rectangle, x, y int) bool {
	cx, cy, rad := r.X+r.Width/2, r.Y+r.Height/2, r.Width/2
	dx, dy := x-cx, y-cy
	return dx*dx+dy*dy <= rad*rad
}

func (u *nativeUI) homeDown(x, y int, button walk.MouseButton) {
	if button != walk.LeftButton || u.view != viewHome {
		return
	}
	switch {
	case inCircle(u.rBtn, x, y):
		u.toggle()
	case inCircle(u.rGear, x, y):
		u.setView(viewSettings)
	case inRect(u.rAbout, x, y):
		u.setView(viewAbout)
	}
}

func (u *nativeUI) homeMove(x, y int, _ walk.MouseButton) {
	if u.hover != 0 {
		u.hover = 0
		u.title.Invalidate()
	}
	if u.view == viewHome && (inCircle(u.rBtn, x, y) || inCircle(u.rGear, x, y) || inRect(u.rAbout, x, y)) {
		u.home.SetCursor(walk.CursorHand())
	} else {
		u.home.SetCursor(walk.CursorArrow())
	}
}

// ---------------------------------------------------------------------------
// Состояние

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
		sig := fmt.Sprintf("%v|%s|%d|%s|%s|%s|%v", on, ts, tp, te, u.a.proxyErr, u.a.settings().Route, u.a.tor.Stalled())
		u.mu.Lock()
		changed := sig != u.lastSig
		u.lastSig = sig
		u.mu.Unlock()
		u.mw.Synchronize(func() {
			// подсветка кнопок заголовка гаснет, когда курсор ушёл
			if u.hover != 0 {
				var p win.POINT
				win.GetCursorPos(&p)
				win.ScreenToClient(u.title.Handle(), &p)
				if u.titleHit(int(p.X), int(p.Y)) != u.hover {
					u.hover = 0
					u.title.Invalidate()
				}
			}
			if !changed {
				return
			}
			u.home.Invalidate()
			if on {
				_ = u.toggleAct.SetText("Выключить обход")
				_ = u.ni.SetToolTip("Обход — шифрование включено")
			} else {
				_ = u.toggleAct.SetText("Включить обход")
				_ = u.ni.SetToolTip("Обход — выключен")
			}
		})
	}
}

func (u *nativeUI) toggle() {
	u.mu.Lock()
	if u.busy {
		u.mu.Unlock()
		return
	}
	u.busy, u.errText = true, ""
	u.mu.Unlock()
	u.home.Invalidate()
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
		u.mw.Synchronize(func() { u.home.Invalidate() })
	}()
}

// loadIP узнаёт внешний IP и страну, загружает флаг.
func (u *nativeUI) loadIP() {
	u.mu.Lock()
	u.ip = "…"
	u.mu.Unlock()
	u.mw.Synchronize(func() { u.home.Invalidate() })
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
			// флаг на белом фоне плашки, без прозрачности
			dst := image.NewRGBA(img.Bounds())
			draw.Draw(dst, dst.Bounds(), &image.Uniform{cWhite.rgba(255)}, image.Point{}, draw.Src)
			draw.Draw(dst, dst.Bounds(), img, img.Bounds().Min, draw.Over)
			if bmp, err := walk.NewBitmapFromImageForDPI(dst, 96); err == nil {
				if u.flagBmp != nil {
					u.flagBmp.Dispose()
				}
				u.flagBmp, u.flagCC = bmp, cc
			}
		}
		u.mu.Unlock()
		u.home.Invalidate()
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

// ---------------------------------------------------------------------------
// Настройки (в этом же окне)

func indexOf(list []string, v string) int {
	for i, x := range list {
		if x == v {
			return i
		}
	}
	return 0
}

func (u *nativeUI) settingsWidgets() []dcl.Widget {
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
		cbRoute, cbStrat, cbBridges, cbDoH *walk.ComboBox
		teCustom, teTest, teSites, teLog   *walk.TextEdit
		btnTest                            *walk.PushButton
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
		cbBridges.SetEnabled(s.Route != RouteDPI)
		go func() {
			if err := u.a.applySettings(s); err != nil {
				u.mw.Synchronize(func() { walk.MsgBox(u.mw, "Настройки", err.Error(), walk.MsgBoxIconWarning) })
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
					lines = append(lines, fmt.Sprintf("%s: %s  %s", r.Name, mark, r.Info))
				}
				out = strings.Join(lines, "\r\n")
			}
			u.mw.Synchronize(func() {
				_ = teTest.SetText(out)
				btnTest.SetEnabled(true)
			})
		}()
	}

	// Обработчики изменений включаются после создания окна (иначе сработали бы при начальной установке значений).
	u.settingsReady = func() { ready = true }

	// Обновление журнала, сайтов и состояния Tor, пока открыты настройки.
	u.refreshSettings = func() {
		if !ready {
			return
		}
		u.a.mu.Lock()
		logs := strings.Join(u.a.logs, "\r\n")
		u.a.mu.Unlock()
		if teLog.Text() != logs {
			_ = teLog.SetText(logs)
			teLog.SendMessage(win.EM_LINESCROLL, 0, 100000)
		}
		if sx := sites(); teSites.Text() != sx {
			_ = teSites.SetText(sx)
		}
		ts, tp, te := u.a.tor.Status()
		t := ""
		switch ts {
		case "ready":
			t = "Tor подключён"
		case "starting":
			t = fmt.Sprintf("Tor подключается… %d%%", tp)
			if u.a.tor.Stalled() {
				t += "\n" + StallHint
			}
		case "error":
			t = te
		}
		_ = lblTor.SetText(t)
	}
	go func() {
		for range time.Tick(time.Second) {
			if u.mw != nil && u.view == viewSettings {
				u.mw.Synchronize(u.refreshSettings)
			}
		}
	}()

	groupFont := dcl.Font{Family: "Segoe UI", PointSize: 9, Bold: true}
	return []dcl.Widget{
		dcl.GroupBox{
			Title: "Подключение", Font: groupFont,
			Layout: dcl.Grid{Columns: 2},
			Children: []dcl.Widget{
				dcl.Label{Text: "Маршрут:"},
				dcl.ComboBox{AssignTo: &cbRoute, Model: routeNames, CurrentIndex: indexOf(routeIDs, st.Route), OnCurrentIndexChanged: apply},
				dcl.Label{Text: "Метод обхода DPI:"},
				dcl.ComboBox{AssignTo: &cbStrat, Model: stratNames, CurrentIndex: indexOf(stratIDs, st.Mode), OnCurrentIndexChanged: apply},
				dcl.Label{Text: "Мосты Tor:"},
				dcl.ComboBox{AssignTo: &cbBridges, Model: bridgeNames, CurrentIndex: indexOf(bridgeOrder, st.Bridges), OnCurrentIndexChanged: apply,
					Enabled: st.Route != RouteDPI},
				dcl.Label{ColumnSpan: 2, Text: "Свои мосты (WebTunnel / obfs4 из Telegram-бота @GetBridgesBot), по одному в строке.\nИспользуются в режимах «Свои мосты» и «Автовыбор»:", TextColor: cMuted.walk()},
				dcl.TextEdit{AssignTo: &teCustom, ColumnSpan: 2, MinSize: dcl.Size{Height: 64}, VScroll: true,
					Text: strings.ReplaceAll(st.CustomBridges, "\n", "\r\n"), Font: dcl.Font{Family: "Consolas", PointSize: 8}},
				dcl.PushButton{ColumnSpan: 2, Text: "Сохранить свои мосты", OnClicked: func() {
					s := u.a.settings()
					s.CustomBridges = strings.ReplaceAll(teCustom.Text(), "\r\n", "\n")
					go func() { _ = u.a.applySettings(s) }()
				}},
				dcl.Label{AssignTo: &lblTor, ColumnSpan: 2, TextColor: cOk.walk()},
			},
		},
		dcl.GroupBox{
			Title: "Проверить сайт", Font: groupFont,
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
				dcl.TextEdit{AssignTo: &teTest, ReadOnly: true, VScroll: true, MinSize: dcl.Size{Height: 100},
					Font: dcl.Font{Family: "Segoe UI", PointSize: 8}},
			},
		},
		dcl.GroupBox{
			Title: "Сайты", Font: groupFont,
			Layout: dcl.VBox{},
			Children: []dcl.Widget{
				dcl.TextEdit{AssignTo: &teSites, ReadOnly: true, VScroll: true, MinSize: dcl.Size{Height: 70}, Text: sites()},
				dcl.PushButton{Text: "Забыть все сайты", OnClicked: func() {
					u.a.eng.Forget("")
					_ = teSites.SetText(sites())
				}},
			},
		},
		dcl.GroupBox{
			Title: "Дополнительно", Font: groupFont,
			Layout: dcl.Grid{Columns: 2},
			Children: []dcl.Widget{
				dcl.Label{Text: "Шифрованный DNS:"},
				dcl.ComboBox{AssignTo: &cbDoH, Model: dohNames, CurrentIndex: indexOf(dohIDs, st.DoH), OnCurrentIndexChanged: apply},
				dcl.CheckBox{AssignTo: &chkSys, ColumnSpan: 2, Text: "Системный прокси (иначе укажите 127.0.0.1 в программах)", Checked: st.SysProxy, OnCheckedChanged: apply},
				dcl.CheckBox{AssignTo: &chkAuto, ColumnSpan: 2, Text: "Включать обход при запуске программы", Checked: st.AutoStart, OnCheckedChanged: apply},
				dcl.Label{Text: "Порт прокси:"},
				dcl.NumberEdit{AssignTo: &nePort, Value: float64(st.Port), MinValue: 1024, MaxValue: 65535, Decimals: 0, OnValueChanged: apply},
			},
		},
		dcl.GroupBox{
			Title: "Журнал", Font: groupFont,
			Layout: dcl.VBox{},
			Children: []dcl.Widget{
				dcl.TextEdit{AssignTo: &teLog, ReadOnly: true, VScroll: true, MinSize: dcl.Size{Height: 130},
					Font: dcl.Font{Family: "Consolas", PointSize: 8}},
			},
		},
		dcl.Composite{
			Layout: dcl.HBox{MarginsZero: true},
			Children: []dcl.Widget{
				dcl.PushButton{Text: "← Назад", OnClicked: func() { u.setView(viewHome) }},
				dcl.HSpacer{},
				dcl.PushButton{Text: "Выход из программы", OnClicked: func() {
					if walk.MsgBox(u.mw, "Обход", "Выключить обход и закрыть программу?", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) == win.IDYES {
						go u.quit()
					}
				}},
			},
		},
	}
}
