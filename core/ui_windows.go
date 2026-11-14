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
// Палитра Aristocrat NET: глубокий синий, королевский синий, небесный, золото.

type rgb struct{ r, g, b uint8 }

var (
	cBg        = rgb{0x0A, 0x0F, 0x1F} // фон
	cBgGrad    = rgb{0x10, 0x25, 0x42}
	cDeep      = rgb{0x0B, 0x2D, 0x6B} // глубокий синий
	cRoyal     = rgb{0x1E, 0x63, 0xD3} // королевский синий
	cSky       = rgb{0x4D, 0xA8, 0xFF} // небесный
	cLight     = rgb{0xB7, 0xE0, 0xFF} // светло-синий
	cGold      = rgb{0xD4, 0xAF, 0x37}
	cGoldLight = rgb{0xF7, 0xE7, 0xB8}
	cTurq      = rgb{0x00, 0xE5, 0xFF}
	cAccent    = rgb{0x00, 0x86, 0xFF}
	cSteel     = rgb{0x7B, 0x8C, 0xA7}
	cDarkGray  = rgb{0x2A, 0x2F, 0x45}
	cCard      = rgb{0x11, 0x1A, 0x33} // карточки и поля
	cCardHover = rgb{0x18, 0x26, 0x4A}
	cLine      = rgb{0x22, 0x2E, 0x52} // разделители, рамки
	cDanger    = rgb{0xFF, 0x6B, 0x6B}

	cNavy      = cBg // заголовок, рамка окна
	cNavyHover = rgb{0x16, 0x21, 0x3D}
	cCloseHov  = rgb{0xC4, 0x2B, 0x1C}
	cText      = rgb{0xEE, 0xF3, 0xFB}
	cMuted     = cSteel
	cWhite     = rgb{0xFF, 0xFF, 0xFF}
	cPillLine  = cGold
	cSkyCenter = cDeep // фон главного экрана: от центра к краю
	cSkyEdge   = cBg
	cOnSky     = rgb{0xFF, 0xFF, 0xFF}
	cOnSkySub  = cLight
	cOnSkyWarn = cGoldLight
	cOnSkyOk   = cGoldLight
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
			col := lerp(cSkyCenter, cSkyEdge, math.Sqrt(clamp01(r)))
			ray := math.Pow(math.Max(0, math.Cos(math.Atan2(dy, dx)*18)), 8) * 0.22 * math.Max(0, 1-r*1.1)
			col = lerp(col, cSky, ray)
			if h := hash2(x*7+3, y*13+5); h > 0.9993 { // звёзды
				col = lerp(col, cLight, 0.5)
			}
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
			if d > R-1 && d < outer { // голубое сияние вокруг планеты
				t := (d - R) / float64(halo)
				gc, ga := cSky, 0.55
				if !vivid {
					gc, ga = cSteel, 0.25
				}
				fillPx(img, x, y, gc, ga*math.Pow(1-clamp01(t), 2))
			}
			cov := clamp01(R - d + 0.5)
			if cov <= 0 {
				continue
			}
			nx, ny := fx/R, fy/R
			nd := math.Min(1, d/R)
			light := clamp01(0.55 - 0.45*(nx*0.6+ny*0.75) + 0.25*(1-nd*nd))
			col := lerp(cDeep, cRoyal, light)
			k := 1 / (math.Sqrt(math.Max(0.05, 1-nd*nd)) + 1.2) * 1.6
			if n := fbm(nx*k*2.0+5.3, ny*k*2.0+1.9); n > 0.45 {
				land := lerp(cSky, cLight, light*0.8)
				col = lerp(col, land, math.Min(1, (n-0.45)*7*1.6)*0.85)
				if n > 0.55 && light < 0.6 && hash2(x, y) > 0.985 { // огни городов
					col = lerp(col, cGoldLight, 0.7)
				}
			}
			if !vivid {
				g := (int(col.r) + int(col.g) + int(col.b)) / 3
				gray := rgb{uint8(g), uint8(g), uint8(math.Min(255, float64(g+18)))}
				col = lerp(lerp(col, gray, 0.65), rgb{}, 0.25)
			}
			if busy {
				col = lerp(col, cAccent, 0.3)
			}
			// атмосферная кайма
			rim := clamp01(1 - math.Abs(R-1.5-d)/1.5)
			rc := rgb{160, 215, 255}
			if !vivid {
				rc = rgb{150, 160, 175}
			}
			col = lerp(col, rc, rim*0.55)
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
	setPane   *walk.CustomWidget // настройки: страницы рисуются сами (как в мобильных приложениях)
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
	brandImg image.Image
	logoBmp  map[string]*walk.Bitmap
	flagBmp  *walk.Bitmap

	// области щелчков (пиксели)
	rBtn, rGear, rAbout, rPill walk.Rectangle

	// Настройки: текущая страница, прокрутка, подсветка, поля ввода.
	page      string
	scroll    int
	setHover  int
	setItems  []*sItem
	natives   map[win.HWND]walk.Rectangle // где сейчас стоят поля ввода
	teBridges *walk.TextEdit
	leHost    *walk.LineEdit
	teResult  *walk.TextEdit
	lePort    *walk.LineEdit
	teLog     *walk.TextEdit
	teSites   *walk.TextEdit
	testing   bool
	contentH  int
	lastPaneW int
	lastPaneH int

	aboutFromSettings bool
	toast             string
	toastAt           time.Time
}

func runDesktopUI(a *App, url string, show bool, quit func(), done <-chan struct{}) {
	u := &nativeUI{a: a, quit: quit, view: viewHome, txt: gdiText{fonts: map[fontKey]win.HFONT{}}, logoBmp: map[string]*walk.Bitmap{}}
	if img, _, err := image.Decode(bytes.NewReader(logoPNG)); err == nil {
		u.logoImg = img
	}
	if img, _, err := image.Decode(bytes.NewReader(brandPNG)); err == nil {
		u.brandImg = img
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
	u.natives = map[win.HWND]walk.Rectangle{}

	if err := (dcl.MainWindow{
		AssignTo:   &u.mw,
		Title:      appTitle,
		Icon:       icon,
		Size:       dcl.Size{Width: 440, Height: 660},
		Background: dcl.SolidColorBrush{Color: cNavy.walk()}, // это цвет рамки окна (1 пиксель)
		// Своя раскладка: заголовок ровно 40 точек, содержимое — всё остальное.
		Layout: frameLayoutDecl{title: func() win.HWND {
			if u.title == nil {
				return 0
			}
			return u.title.Handle()
		}, fixed: func() map[win.HWND]walk.Rectangle {
			out := make(map[win.HWND]walk.Rectangle, len(u.natives))
			for h, r := range u.natives {
				out[h] = r
			}
			return out
		}},
		Children: []dcl.Widget{
			dcl.CustomWidget{
				AssignTo:            &u.title,
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
			dcl.CustomWidget{
				AssignTo:            &u.setPane,
				Visible:             false,
				PaintPixels:         u.paintSettings,
				InvalidatesOnResize: true,
				DoubleBuffering:     true,
				OnMouseDown:         u.settingsDown,
				OnMouseMove:         u.settingsMove,
				OnKeyDown: func(key walk.Key) {
					if key == walk.KeyEscape {
						u.goBack()
					}
				},
			},
			dcl.TextEdit{AssignTo: &u.teBridges, Visible: false, VScroll: true, Font: dcl.Font{Family: "Consolas", PointSize: 9}},
			dcl.LineEdit{AssignTo: &u.leHost, Visible: false, CueBanner: "например, youtube.com", Font: dcl.Font{Family: "Segoe UI", PointSize: 11},
				OnKeyDown: func(k walk.Key) {
					if k == walk.KeyReturn {
						u.runTest()
					}
				}},
			dcl.TextEdit{AssignTo: &u.teResult, Visible: false, ReadOnly: true, VScroll: true, Font: dcl.Font{Family: "Segoe UI", PointSize: 9}},
			dcl.LineEdit{AssignTo: &u.lePort, Visible: false, Font: dcl.Font{Family: "Segoe UI", PointSize: 11}},
			dcl.TextEdit{AssignTo: &u.teLog, Visible: false, ReadOnly: true, VScroll: true, Font: dcl.Font{Family: "Consolas", PointSize: 8}},
			dcl.TextEdit{AssignTo: &u.teSites, Visible: false, ReadOnly: true, VScroll: true, Font: dcl.Font{Family: "Segoe UI", PointSize: 9}},
		},
	}.Create()); err != nil {
		return err
	}
	if icon != nil {
		_ = u.mw.SetIcon(icon)
	}
	u.styleNatives()
	u.setPane.MouseWheel().Attach(func(x, y int, b walk.MouseButton) {
		u.scrollBy(-int(int16(uint32(b)>>16)) * int(48*u.dpiScale()) / 120)
	})

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
	_ = ni.SetToolTip(appTitle)
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
	add("Открыть "+appTitle, u.showWindow)
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
	// После смены стиля клиентская область стала больше — пересчитываем раскладку,
	// чтобы снизу не оставалось пустой полосы.
	u.mw.RequestLayout()
	u.title.Invalidate()
	u.home.Invalidate()
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
		_ = u.ni.ShowInfo(appTitle+" продолжает работать", "Окно свёрнуто в трей. Щёлкните по значку, чтобы открыть его снова.")
	}
}

func (u *nativeUI) setView(v string) {
	u.view = v
	settings := v == viewSettings
	if settings {
		u.page, u.scroll = "root", 0
	}
	u.setPane.SetVisible(settings)
	u.home.SetVisible(!settings)
	u.showPage()
	u.title.Invalidate()
	u.home.Invalidate()
	if !settings {
		_ = u.home.SetFocus()
	} else {
		_ = u.setPane.SetFocus()
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
	fTitle := u.txt.font("Segoe UI Semibold", int(14*s), false)
	if u.view != viewHome {
		u.txt.draw(hdc, "←", u.txt.font("Segoe UI", int(18*s), false), cGoldLight, back, dtCenter|dtVCenter|dtSingle)
		x = back.Width + int(4*s)
		title := "О программе"
		if u.view == viewSettings {
			title = u.pageTitle()
		}
		u.txt.draw(hdc, title, fTitle, cText,
			walk.Rectangle{X: x, Y: 0, Width: min.X - x, Height: b.Height}, dtLeft|dtVCenter|dtSingle)
	} else {
		lp := int(24 * s)
		if bmp := u.logoBitmap(lp, cNavy); bmp != nil {
			_ = c.DrawImagePixels(bmp, walk.Point{X: x, Y: (b.Height - lp) / 2})
		}
		x += lp + int(9*s)
		w1, _ := u.txt.measure(hdc, "Aristocrat ", fTitle)
		u.txt.draw(hdc, "Aristocrat ", fTitle, cGold, walk.Rectangle{X: x, Y: 0, Width: w1 + 2, Height: b.Height}, dtLeft|dtVCenter|dtSingle)
		u.txt.draw(hdc, "NET", fTitle, cLight, walk.Rectangle{X: x + w1, Y: 0, Width: min.X - x - w1, Height: b.Height}, dtLeft|dtVCenter|dtSingle)
	}
	// тонкая золотая линия под заголовком
	gl, _ := walk.NewSolidColorBrush(cLine.walk())
	_ = c.FillRectanglePixels(gl, walk.Rectangle{X: 0, Y: b.Height - 1, Width: b.Width, Height: 1})
	gl.Dispose()

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
		u.goBack()
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
	upLines, upWarns := u.a.upstreamLines()
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
	pillY := stateY + int(96*s)
	u.rPill = walk.Rectangle{X: (b.Width - pillW) / 2, Y: pillY, Width: pillW, Height: pillH}

	// Фон и фигуры — одной сглаженной картинкой (пересчитывается только при изменениях).
	key := sceneKey{w: b.Width, h: b.Height, state: state, view: u.view, pill: u.rPill, gear: u.rGear, btn: u.rBtn}
	if u.scene == nil || key != u.sceneKey {
		img := image.NewRGBA(image.Rect(0, 0, b.Width, b.Height))
		if u.view == viewHome {
			sky(img, float64(u.rBtn.X+u.rBtn.Width/2), float64(u.rBtn.Y+u.rBtn.Height/2))
			planet(img, u.rBtn, int(16*s), state != "off", state == "busy")
			roundRect(img, u.rPill, float64(pillH)/2, cCard, cPillLine)
			circleShape(img, u.rGear, cCard, cLine)
		} else {
			lp := int(210 * s)
			ly := int(16 * s)
			sky(img, float64(b.Width)/2, float64(ly+lp/2))
			if u.brandImg != nil {
				logo := scaleRGBA(u.brandImg, lp)
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
	u.txt.draw(hdc, label, fBtn, cBg, sh, dtCenter|dtVCenter|dtSingle)
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
		sub = routeSummary(st)
		if len(upLines) > 0 {
			sub += "\n" + strings.Join(upLines, " · ")
		}
	}
	u.txt.draw(hdc, sub, u.txt.font("Segoe UI", int(13*s), false), cOnSkySub,
		walk.Rectangle{X: int(20 * s), Y: stateY + int(32*s), Width: b.Width - int(40*s), Height: int(58 * s)}, dtCenter|dtWord)

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
	if on {
		msgs = append(msgs, upWarns...)
	}
	if len(msgs) > 0 {
		y := pillY + pillH + int(14*s)
		u.txt.draw(hdc, strings.Join(msgs, "\n"), u.txt.font("Segoe UI", int(12*s), false), cOnSkyWarn,
			walk.Rectangle{X: int(24 * s), Y: y, Width: b.Width - int(48*s), Height: u.rGear.Y - y - int(6*s)}, dtCenter|dtWord)
	}

	// Шестерёнка
	u.txt.draw(hdc, "⚙", u.txt.font("Segoe UI Symbol", int(23*s), false), cLight, u.rGear, dtCenter|dtVCenter|dtSingle)
	u.txt.draw(hdc, "v"+appVersion, u.txt.font("Segoe UI", int(11*s), false), cOnSkySub,
		walk.Rectangle{X: 0, Y: u.rGear.Y, Width: b.Width - int(16*s), Height: u.rGear.Height}, dtRight|dtVCenter|dtSingle)
	return nil
}

func (u *nativeUI) paintAbout(c *walk.Canvas, hdc win.HDC, b walk.Rectangle, s float64) {
	y := int(16*s) + int(210*s) + int(8*s)
	u.txt.draw(hdc, "версия "+appVersion, u.txt.font("Segoe UI", int(13*s), false), cGoldLight,
		walk.Rectangle{Y: y, Width: b.Width, Height: int(20 * s)}, dtCenter|dtSingle)
	y += int(30 * s)
	text := "Шифрует DNS и обходит блокировки провайдера прямо на компьютере — без VPN-подписок и своих серверов.\n\n" +
		"Сначала соединение идёт напрямую: начало защищённого соединения нарезается так, что фильтр провайдера (DPI) " +
		"не узнаёт сайт. Если сайт заблокирован по IP или обход не помог — соединение автоматически идёт через " +
		"бесплатный Cloudflare WARP (сайт видит IP Cloudflare, а не ваш) или сеть Tor. " +
		"Российские и казахстанские сайты всегда открываются с вашим настоящим IP.\n\n" +
		"Используются: wireguard-go, gVisor, Tor и lyrebird. Лицензия MIT."
	u.txt.draw(hdc, text, u.txt.font("Segoe UI", int(13*s), false), cText,
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
		ul, uw := u.a.upstreamLines()
		st := u.a.settings()
		sig := fmt.Sprintf("%v|%v|%v|%s|%s|%s", on, ul, uw, u.a.proxyErr, st.Route, st.Heavy)
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
			if u.view == viewSettings {
				u.refreshPage()
			}
			if !changed {
				return
			}
			u.home.Invalidate()
			if on {
				_ = u.toggleAct.SetText("Выключить обход")
				_ = u.ni.SetToolTip(appTitle + " — шифрование включено")
			} else {
				_ = u.toggleAct.SetText("Включить обход")
				_ = u.ni.SetToolTip(appTitle + " — выключено")
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
