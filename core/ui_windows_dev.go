//go:build windows

package main

// Windows: раздел разработчика (сборка разработчика), значок антенны на главном экране,
// переключатель раздачи в трее и предупреждение для пользователей при выборе
// режима «Через разработчика».

import (
	"image"
	"io"
	"math"
	"os"
	"strings"
	"time"

	"github.com/lxn/walk"
)

// showAnt — показывать антенну раздачи на главном экране.
func (u *nativeUI) showAnt() bool { return devBuild && u.a.settings().DevMode }

func (u *nativeUI) antRect() walk.Rectangle {
	s := u.dpiScale()
	r := u.rGear
	r.X += r.Width + int(12*s)
	return r
}

// drawAntenna — кнопка-антенна: мачта, точка и «волны» (золотые, когда раздача включена).
func (u *nativeUI) drawAntenna(img *image.RGBA) {
	r := u.antRect()
	on := u.a.dev.On()
	ring, col := cLine, cSteel
	if on {
		ring, col = cGold, cGoldLight
	}
	circleShape(img, r, cCard, ring)
	cx, cy := float64(r.X)+float64(r.Width)/2, float64(r.Y)+float64(r.Height)*0.45
	s := float64(r.Width) / 44
	// мачта
	for y := cy; y < float64(r.Y)+float64(r.Height)*0.78; y++ {
		for x := cx - 1.2*s; x <= cx+1.2*s; x++ {
			fillPx(img, int(x), int(y), col, 1)
		}
	}
	// точка и две пары дуг
	drawRing(img, cx, cy, 0, 2.6*s, 0, 2*math.Pi, col)
	for _, rr := range []float64{7 * s, 12 * s} {
		drawRing(img, cx, cy, rr, 1.6*s, -0.75, 0.75, col)                // справа
		drawRing(img, cx, cy, rr, 1.6*s, math.Pi-0.75, math.Pi+0.75, col) // слева
	}
}

// drawRing рисует сглаженную дугу (r — радиус середины, w — толщина, углы в радианах).
func drawRing(img *image.RGBA, cx, cy, r, w, a0, a1 float64, col rgb) {
	ext := r + w
	for y := int(cy - ext - 1); y <= int(cy+ext+1); y++ {
		for x := int(cx - ext - 1); x <= int(cx+ext+1); x++ {
			dx, dy := float64(x)+0.5-cx, float64(y)+0.5-cy
			d := math.Hypot(dx, dy)
			cov := clamp01(w/2 + 0.5 - math.Abs(d-r))
			if r == 0 {
				cov = clamp01(w + 0.5 - d)
			}
			if cov <= 0 {
				continue
			}
			if r > 0 {
				ang := math.Atan2(dy, dx)
				in := (ang >= a0 && ang <= a1) || (ang+2*math.Pi >= a0 && ang+2*math.Pi <= a1)
				if !in {
					continue
				}
			}
			fillPx(img, x, y, col, cov)
		}
	}
}

// toggleShare — антенна, трей, переключатель в настройках.
func (u *nativeUI) toggleShare() {
	on := !u.a.dev.On()
	go func() {
		err := u.a.devSetShare(on)
		u.mw.Synchronize(func() {
			if err != nil {
				walk.MsgBox(u.mw, appTitle, err.Error(), walk.MsgBoxIconWarning)
			}
			u.home.Invalidate()
			u.setPane.Invalidate()
		})
	}()
}

// devItems — раздел «Разработчик» на главной странице настроек.
func (u *nativeUI) devItems(st Settings) []*sItem {
	if !devBuild {
		return nil
	}
	if !st.DevMode {
		return []*sItem{section("Разработчик"), row("Режим разработчика", "", "Выключен", u.open("devlogin"))}
	}
	return []*sItem{
		section("Разработчик"),
		toggleRow("Раздача интернета", u.a.dev.Status(), u.a.dev.On(), u.toggleShare),
		row("Ключ и код подключения", "", "", u.open("devkey")),
		row("Журнал подключений", "", "", u.open("devlog")),
		{kind: kRow, title: "Выключить режим разработчика", danger: true, act: func() {
			u.a.devLock()
			u.showPage()
			u.home.Invalidate()
		}},
	}
}

// devPage — страницы раздела разработчика (nil — не страница раздела).
func (u *nativeUI) devPage(id string) *sPage {
	if !devBuild {
		return nil
	}
	switch id {
	case "devlogin":
		return &sPage{title: "Режим разработчика", parent: "root", items: []*sItem{
			{kind: kText, title: "Введите пароль разработчика. После входа появятся раздача интернета, ключ сервера и журнал подключений."},
			{kind: kNative, native: u.lePass, h: 30},
			{kind: kButtons, btns: []*sBtn{{label: "Включить", primary: true, act: u.devLogin}}},
		}}
	case "devkey":
		return &sPage{title: "Ключ и код подключения", parent: "root", items: []*sItem{
			section("Код подключения"),
			{kind: kText, title: "Включите раздачу, скопируйте код и вставьте его в секрет GitHub DEV_DIRECT — " +
				"в пользовательских сборках появится маршрут «Ебаная Чукотка». Нужен белый IP и открытый порт 443 (или 8443)."},
			{kind: kButtons, btns: []*sBtn{{label: "Копировать код подключения", primary: true, act: func() {
				go func() {
					c, err := u.a.dev.Code()
					u.mw.Synchronize(func() {
						if err != nil {
							walk.MsgBox(u.mw, appTitle, err.Error(), walk.MsgBoxIconInformation)
						} else if walk.Clipboard().SetText(c) == nil {
							u.showToast("Код скопирован — вставьте его в секрет DEV_DIRECT")
						}
					})
				}()
			}}}},
			section("Ключ сервера"),
			{kind: kText, title: "Ключ — сертификат сервера и ключ доступа. Сохраните копию: после переустановки Windows " +
				"восстановите ключ, и код подключения останется прежним — пересобирать приложения не придётся. Никому его не передавайте."},
			{kind: kButtons, btns: []*sBtn{
				{label: "Копировать ключ", act: u.devCopyKey},
				{label: "Сохранить в файл", act: u.devSaveFile},
			}},
			{kind: kButtons, btns: []*sBtn{
				{label: "Сохранить в облако", act: u.devSaveCloud},
			}},
			{kind: kButtons, btns: []*sBtn{
				{label: "Вставить ключ", act: u.devPasteKey},
				{label: "Восстановить из файла", act: u.devOpenFile},
			}},
		}}
	case "devlog":
		return &sPage{title: "Журнал подключений", parent: "root", items: []*sItem{
			{kind: kButtons, btns: []*sBtn{
				{label: "Копировать", primary: true, act: func() {
					if walk.Clipboard().SetText(u.a.dev.JournalText()) == nil {
						u.showToast("Журнал скопирован")
					}
				}},
				{label: "Очистить", act: func() {
					u.a.dev.ClearJournal()
					u.refreshPage()
				}},
			}},
			{kind: kNative, native: u.teDevLog},
		}}
	}
	return nil
}

func (u *nativeUI) devLogin() {
	pass := u.lePass.Text()
	go func() {
		err := u.a.devUnlock(pass)
		if err != nil {
			time.Sleep(time.Second) // перебор паролей — медленно
		}
		u.mw.Synchronize(func() {
			if err != nil {
				walk.MsgBox(u.mw, appTitle, err.Error(), walk.MsgBoxIconWarning)
				return
			}
			_ = u.lePass.SetText("")
			u.page, u.scroll = "root", 0
			u.showPage()
			u.home.Invalidate()
			u.showToast("Режим разработчика включён")
		})
	}()
}

func (u *nativeUI) devCopyKey() {
	k, err := u.a.dev.ExportKey()
	if err != nil {
		walk.MsgBox(u.mw, appTitle, err.Error(), walk.MsgBoxIconInformation)
		return
	}
	if walk.Clipboard().SetText(k) == nil {
		u.showToast("Ключ скопирован — храните его в надёжном месте")
	}
}

func (u *nativeUI) devSaveFile() {
	if _, err := u.a.dev.ExportKey(); err != nil {
		walk.MsgBox(u.mw, appTitle, err.Error(), walk.MsgBoxIconInformation)
		return
	}
	dlg := &walk.FileDialog{Title: "Сохранить ключ разработчика", Filter: "Текстовый файл (*.txt)|*.txt",
		FilePath: "AristocratNET-ключ-разработчика.txt"}
	if ok, err := dlg.ShowSave(u.mw); err != nil || !ok {
		return
	}
	p := dlg.FilePath
	if !strings.HasSuffix(strings.ToLower(p), ".txt") {
		p += ".txt"
	}
	if err := u.a.dev.SaveKey(p); err != nil {
		walk.MsgBox(u.mw, appTitle, "Не удалось сохранить: "+err.Error(), walk.MsgBoxIconWarning)
		return
	}
	u.showToast("Ключ сохранён")
}

func (u *nativeUI) devSaveCloud() {
	paths, err := u.a.dev.SaveKeyToCloud()
	if err != nil {
		walk.MsgBox(u.mw, appTitle, err.Error(), walk.MsgBoxIconInformation)
		return
	}
	walk.MsgBox(u.mw, appTitle, "Ключ сохранён:\n"+strings.Join(paths, "\n"), walk.MsgBoxIconInformation)
}

func (u *nativeUI) devImport(text string) {
	go func() {
		err := u.a.dev.ImportKey(text)
		u.mw.Synchronize(func() {
			if err != nil {
				walk.MsgBox(u.mw, appTitle, err.Error(), walk.MsgBoxIconWarning)
				return
			}
			u.showPage()
			u.showToast("Ключ восстановлен")
		})
	}()
}

func (u *nativeUI) devPasteKey() {
	t, err := walk.Clipboard().Text()
	if err != nil || strings.TrimSpace(t) == "" {
		walk.MsgBox(u.mw, appTitle, "В буфере обмена нет ключа. Скопируйте ключ и нажмите «Вставить ключ» ещё раз.", walk.MsgBoxIconInformation)
		return
	}
	u.devImport(t)
}

func (u *nativeUI) devOpenFile() {
	dlg := &walk.FileDialog{Title: "Ключ разработчика", Filter: "Текстовый файл (*.txt)|*.txt|Все файлы (*.*)|*.*"}
	if ok, err := dlg.ShowOpen(u.mw); err != nil || !ok {
		return
	}
	b, err := readSmallFile(dlg.FilePath)
	if err != nil {
		walk.MsgBox(u.mw, appTitle, "Не удалось прочитать файл: "+err.Error(), walk.MsgBoxIconWarning)
		return
	}
	u.devImport(b)
}

// confirmDevRoute — предупреждение перед выбором режима «Через разработчика».
func (u *nativeUI) confirmDevRoute(apply func()) {
	p := &popup{u: u, dialog: true, title: "Подключиться через разработчика?",
		text: "Интернет пойдёт через сервер разработчика: сайты увидят его IP. " +
			"Разработчик увидит имя вашего устройства, ваш IP-адрес, город и страну, версию приложения и объём трафика."}
	p.items = []*popItem{
		{label: "Отмена", button: true},
		{label: "Подключиться", button: true, primary: true, act: apply},
	}
	p.show(0, 0)
}

// refreshDevLog — журнал на странице обновляется раз в секунду.
func (u *nativeUI) refreshDevLog() {
	if u.page != "devlog" || u.teDevLog == nil {
		return
	}
	if t := u.a.dev.JournalText(); u.teDevLog.Text() != t {
		_ = u.teDevLog.SetText(t)
	}
}

// readSmallFile — текст файла ключа (не больше 64 КБ).
func readSmallFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64<<10))
	return string(b), err
}
