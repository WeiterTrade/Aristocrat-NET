//go:build windows

package main

// Раздача и приём интернета в окне Windows: две кнопки на главном экране, пункты в трее,
// раздел в настройках (см. lan.go).

import (
	"strings"

	"github.com/lxn/walk"
)

func (u *nativeUI) lanItems() []*sItem {
	shareOn, bypass := u.a.shareOn()
	recvOn, host, rerr := u.a.recvOn()
	shareSub := "Устройства вашей сети получат интернет через этот компьютер"
	if shareOn {
		if addrs := lanAddrs(); len(addrs) > 0 {
			shareSub = "Адрес: " + strings.Join(addrs, ", ") + ", порт 8282"
		} else {
			shareSub = "Компьютер не подключён к сети — подключите его к Wi-Fi или включите «Мобильный хот-спот»"
		}
	}
	recvSub := "Компьютер подключён к точке доступа телефона, на котором включена «Раздача»"
	switch {
	case recvOn && rerr != "":
		recvSub = rerr
	case recvOn:
		recvSub = "Через телефон " + host
	case rerr != "":
		recvSub = rerr
	}
	items := []*sItem{
		section("Раздача и приём"),
		toggleRow("Раздать интернет", shareSub, shareOn, func() { u.lanShare(!shareOn, bypass) }),
	}
	if shareOn {
		items = append(items, toggleRow("Раздавать с обходом блокировок", "Устройства получат интернет с тем же обходом, что и компьютер",
			bypass, func() { u.lanShare(true, !bypass) }))
	}
	items = append(items,
		toggleRow("Интернет с телефона", recvSub, recvOn, u.recvClick),
		&sItem{kind: kText, title: "Раздача: устройства подключаются к сети этого компьютера (роутер или «Мобильный хот-спот» Windows) " +
			"и включают в Aristocrat NET «Интернет с телефона» или указывают прокси: адрес компьютера, порт 8282.\n" +
			"Приём: подключите компьютер к точке доступа телефона, на телефоне включите «Раздачу» в Aristocrat NET. " +
			"Сайты открывает сам телефон — для оператора это его трафик, а не раздача."},
	)
	return items
}

// lanShare включает (с обходом или без) или выключает раздачу.
func (u *nativeUI) lanShare(on, bypass bool) {
	go func() {
		var err error
		if on {
			err = u.a.shareStart(bypass)
		} else {
			u.a.shareStop()
		}
		u.mw.Synchronize(func() {
			if err != nil {
				walk.MsgBox(u.mw, appTitle, err.Error(), walk.MsgBoxIconWarning)
			}
			u.home.Invalidate()
			u.setPane.Invalidate()
		})
	}()
}

// shareClick — кнопка «Раздать интернет» на главном экране: выбрать, с обходом или без.
func (u *nativeUI) shareClick() {
	if on, _ := u.a.shareOn(); on {
		u.lanShare(false, false)
		return
	}
	addr := strings.Join(lanAddrs(), ", ")
	if addr == "" {
		addr = "адрес этого компьютера"
	}
	p := &popup{u: u, dialog: true, title: "Раздать интернет с компьютера",
		text: "Устройства вашей сети (Wi-Fi роутера или «Мобильного хот-спота» Windows) получат интернет через этот компьютер. " +
			"На них: Aristocrat NET → «Интернет с телефона» или прокси " + addr + ", порт 8282."}
	p.items = []*popItem{
		{label: "Отмена", button: true},
		{label: "Без обхода", button: true, act: func() { u.lanShare(true, false) }},
		{label: "С обходом блокировок", button: true, primary: true, act: func() { u.lanShare(true, true) }},
	}
	p.show(0, 0)
}

// recvClick — «Интернет с телефона»: включить (найти телефон) или выключить.
func (u *nativeUI) recvClick() {
	if on, _, _ := u.a.recvOn(); on {
		go func() {
			u.a.recvStop()
			u.mw.Synchronize(func() { u.home.Invalidate(); u.setPane.Invalidate() })
		}()
		return
	}
	u.mu.Lock()
	if u.recvBusy {
		u.mu.Unlock()
		return
	}
	u.recvBusy, u.errText = true, ""
	u.mu.Unlock()
	u.home.Invalidate()
	go func() {
		err := u.a.recvStart()
		u.mu.Lock()
		u.recvBusy = false
		if err != nil {
			u.errText = err.Error()
		}
		u.mu.Unlock()
		u.mw.Synchronize(func() { u.home.Invalidate(); u.setPane.Invalidate() })
	}()
}

// lanButtons — две кнопки под плашкой IP: «Раздать интернет» и «Интернет с телефона».
func (u *nativeUI) lanButtons(width, y int) {
	s := u.dpiScale()
	bw, bh, gap := int(184*s), int(36*s), int(12*s)
	u.rShare = walk.Rectangle{X: width/2 - gap/2 - bw, Y: y, Width: bw, Height: bh}
	u.rRecv = walk.Rectangle{X: width/2 + gap/2, Y: y, Width: bw, Height: bh}
}

func (u *nativeUI) lanLabels() (share, recv string, shareOn, recvOn bool) {
	shareOn, bypass := u.a.shareOn()
	recvOn, _, _ = u.a.recvOn()
	share, recv = "Раздать интернет", "Интернет с телефона"
	if shareOn {
		share = "● Раздача включена"
		if bypass {
			share = "● Раздача с обходом"
		}
	}
	u.mu.Lock()
	busy := u.recvBusy
	u.mu.Unlock()
	if busy {
		recv = "Ищу телефон…"
	} else if recvOn {
		recv = "● Интернет с телефона"
	}
	return
}
