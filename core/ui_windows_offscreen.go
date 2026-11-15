//go:build windows

package main

// Постоянный внеэкранный буфер для рисования главного экрана и настроек.
//
// Раньше на каждую перерисовку создавались новые картинки и буферы размером с окно
// (на развёрнутом окне — по 8 МБ). В 32-битной программе на Windows 7 такие выделения
// время от времени не удавались, и окно на долю секунды становилось белым-серым.
// Теперь буфер создаётся один раз на размер окна: картинка рисуется в память,
// поверх неё — текст средствами Windows, и всё переносится на экран одним BitBlt.

import (
	"image"
	"image/draw"
	"unsafe"

	"github.com/lxn/walk"
	"github.com/lxn/win"
)

type offscreen struct {
	w, h int
	dc   win.HDC
	bmp  win.HBITMAP
	old  win.HGDIOBJ
	bits []byte      // пиксели DIB (BGRA, сверху вниз)
	img  *image.RGBA // здесь рисуем фигуры (RGBA)
}

func (o *offscreen) ensure(w, h int) bool {
	if w < 1 || h < 1 {
		return false
	}
	if o.dc != 0 && o.w == w && o.h == h {
		return true
	}
	o.free()
	bi := win.BITMAPINFOHEADER{BiWidth: int32(w), BiHeight: -int32(h), BiPlanes: 1, BiBitCount: 32, BiCompression: win.BI_RGB}
	bi.BiSize = uint32(unsafe.Sizeof(bi))
	o.dc = win.CreateCompatibleDC(0)
	if o.dc == 0 {
		return false
	}
	var p unsafe.Pointer
	o.bmp = win.CreateDIBSection(o.dc, &bi, win.DIB_RGB_COLORS, &p, 0, 0)
	if o.bmp == 0 || p == nil {
		win.DeleteDC(o.dc)
		o.dc = 0
		return false
	}
	o.old = win.SelectObject(o.dc, win.HGDIOBJ(o.bmp))
	o.bits = unsafe.Slice((*byte)(p), w*h*4)
	o.img = image.NewRGBA(image.Rect(0, 0, w, h))
	o.w, o.h = w, h
	return true
}

func (o *offscreen) free() {
	if o.dc != 0 {
		win.SelectObject(o.dc, o.old)
		win.DeleteObject(win.HGDIOBJ(o.bmp))
		win.DeleteDC(o.dc)
	}
	o.dc, o.bmp, o.bits, o.img, o.w, o.h = 0, 0, nil, nil, 0, 0
}

// upload переносит нарисованную картинку в DIB (RGBA → BGRA).
func (o *offscreen) upload() {
	src, dst := o.img.Pix, o.bits
	for i := 0; i+3 < len(src) && i+3 < len(dst); i += 4 {
		dst[i], dst[i+1], dst[i+2], dst[i+3] = src[i+2], src[i+1], src[i], 255
	}
}

// blit выводит буфер на экран одним действием — без мигания.
func (o *offscreen) blit(c *walk.Canvas) {
	win.BitBlt(c.HDC(), 0, 0, int32(o.w), int32(o.h), o.dc, 0, 0, win.SRCCOPY)
}

// fillRectImg — заливка прямоугольника в картинке (без сглаживания).
func fillRectImg(img *image.RGBA, r walk.Rectangle, col rgb) {
	draw.Draw(img, image.Rect(r.X, r.Y, r.X+r.Width, r.Y+r.Height), &image.Uniform{col.rgba(255)}, image.Point{}, draw.Src)
}

// drawImageScaled вписывает src в прямоугольник r (усреднение пикселей; для флага и логотипа).
func drawImageScaled(dst *image.RGBA, src image.Image, r walk.Rectangle) {
	sb := src.Bounds()
	if r.Width < 1 || r.Height < 1 || sb.Dx() < 1 || sb.Dy() < 1 {
		return
	}
	sx, sy := float64(sb.Dx())/float64(r.Width), float64(sb.Dy())/float64(r.Height)
	db := dst.Bounds()
	for y := 0; y < r.Height; y++ {
		for x := 0; x < r.Width; x++ {
			if !(image.Point{X: r.X + x, Y: r.Y + y}).In(db) {
				continue
			}
			var cr, cg, cb, ca, n float64
			for yy := int(float64(y) * sy); yy < int(float64(y+1)*sy) || yy == int(float64(y)*sy); yy++ {
				for xx := int(float64(x) * sx); xx < int(float64(x+1)*sx) || xx == int(float64(x)*sx); xx++ {
					pr, pg, pb, pa := src.At(sb.Min.X+xx, sb.Min.Y+yy).RGBA()
					cr, cg, cb, ca, n = cr+float64(pr), cg+float64(pg), cb+float64(pb), ca+float64(pa), n+1
				}
			}
			a := ca / n / 65535
			if a <= 0 {
				continue
			}
			col := rgb{uint8(cr / n / 257 / a), uint8(cg / n / 257 / a), uint8(cb / n / 257 / a)}
			fillPx(dst, r.X+x, r.Y+y, col, a)
		}
	}
}
