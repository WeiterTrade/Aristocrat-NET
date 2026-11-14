//go:build windows

package main

// Собственная раскладка главного окна.
//
// Стандартный VBox из walk распределяет место между заголовком и содержимым
// по своим правилам (жадные виджеты, коэффициенты растяжения), и на части систем
// заголовок получался огромным, а снизу оставалась пустая полоса.
// Здесь всё задано жёстко: заголовок — ровно titleDIP точек сверху,
// всё остальное (главный экран или настройки) — строго под ним до низа окна,
// по краям — рамка в border пикселей (цвет фона окна).

import (
	"github.com/lxn/walk"
	"github.com/lxn/win"
)

const titleDIP = 40

type frameLayout struct {
	*walk.BoxLayout // нужен только ради неэкспортируемых методов интерфейса walk.Layout
	container       walk.Container
	title           func() win.HWND
	fixed           func() map[win.HWND]walk.Rectangle // поля ввода настроек: точное место задаёт страница
}

// frameLayoutDecl — объявление для declarative (Layout: frameLayoutDecl{...}).
type frameLayoutDecl struct {
	title func() win.HWND
	fixed func() map[win.HWND]walk.Rectangle
}

func (d frameLayoutDecl) Create() (walk.Layout, error) {
	l := newFrameLayout(d.title)
	l.fixed = d.fixed
	return l, nil
}

func newFrameLayout(title func() win.HWND) *frameLayout {
	l := &frameLayout{BoxLayout: walk.NewVBoxLayout(), title: title}
	_ = l.BoxLayout.SetMargins(walk.Margins{})
	_ = l.BoxLayout.SetSpacing(0)
	return l
}

func (l *frameLayout) Container() walk.Container { return l.container }

func (l *frameLayout) SetContainer(c walk.Container) {
	if c == l.container {
		return
	}
	l.container = c
	if c != nil {
		if c.Layout() != walk.Layout(l) {
			_ = c.SetLayout(l)
		}
		c.RequestLayout()
	}
}

func (l *frameLayout) CreateLayoutItem(ctx *walk.LayoutContext) walk.ContainerLayoutItem {
	var h win.HWND
	if l.title != nil {
		h = l.title()
	}
	var fixed map[win.HWND]walk.Rectangle
	if l.fixed != nil {
		fixed = l.fixed()
	}
	return &frameLayoutItem{title: h, fixed: fixed}
}

type frameLayoutItem struct {
	walk.ContainerLayoutItemBase
	title win.HWND
	fixed map[win.HWND]walk.Rectangle
}

func (li *frameLayoutItem) dpi() int {
	if ctx := li.Context(); ctx != nil && ctx.DPI() > 0 {
		return ctx.DPI()
	}
	return 96
}

func (*frameLayoutItem) LayoutFlags() walk.LayoutFlags {
	return walk.ShrinkableHorz | walk.ShrinkableVert | walk.GrowableHorz | walk.GrowableVert |
		walk.GreedyHorz | walk.GreedyVert
}

func (li *frameLayoutItem) MinSize() walk.Size {
	d := li.dpi()
	return walk.Size{Width: 300 * d / 96, Height: 360 * d / 96}
}

func (li *frameLayoutItem) MinSizeForSize(walk.Size) walk.Size { return li.MinSize() }
func (*frameLayoutItem) HasHeightForWidth() bool               { return false }
func (li *frameLayoutItem) HeightForWidth(int) int             { return li.MinSize().Height }

func (li *frameLayoutItem) PerformLayout() []walk.LayoutResultItem {
	cs := li.Geometry().ClientSize
	th := titleDIP * li.dpi() / 96
	const border = 1
	var out []walk.LayoutResultItem
	for _, it := range li.Children() {
		if it == nil || !it.Visible() {
			continue
		}
		var r walk.Rectangle
		if fr, ok := li.fixed[it.Handle()]; ok {
			r = fr
		} else if it.Handle() == li.title {
			r = walk.Rectangle{X: 0, Y: 0, Width: cs.Width, Height: th}
		} else {
			r = walk.Rectangle{X: border, Y: th, Width: cs.Width - 2*border, Height: cs.Height - th - border}
		}
		if r.Width < 1 {
			r.Width = 1
		}
		if r.Height < 1 {
			r.Height = 1
		}
		out = append(out, walk.LayoutResultItem{Item: it, Bounds: r})
	}
	return out
}
