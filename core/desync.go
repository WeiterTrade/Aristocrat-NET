package main

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"
)

// Методы обхода DPI. Все они меняют только «нарезку» первых байт соединения:
// сервер получает тот же самый запрос, а DPI не может собрать имя сайта (SNI/Host).
const (
	StratNone         = "none"         // без изменений
	StratTLSRec       = "tlsrec"       // ClientHello делится на две TLS-записи посередине SNI
	StratSplit        = "split"        // ClientHello делится на два TCP-сегмента посередине SNI
	StratTLSRecSplit  = "tlsrec+split" // оба способа сразу
	StratDisorder     = "disorder"     // первый сегмент уходит с TTL=1 и доходит только повторной отправкой
	StratTLSRecDisord = "tlsrec+disorder"
	StratTor          = "tor" // не метод обхода, а маршрут: через Tor
)

// Порядок перебора в авторежиме: от самых дешёвых к самым «тяжёлым».
var AutoOrder = []string{StratTLSRec, StratSplit, StratTLSRecSplit, StratDisorder, StratTLSRecDisord, StratNone}

var StratNames = map[string]string{
	StratNone:         "Без изменений",
	StratTLSRec:       "Дробление TLS-записи",
	StratSplit:        "Разбиение TCP",
	StratTLSRecSplit:  "TLS-запись + TCP",
	StratDisorder:     "Disorder (TTL)",
	StratTLSRecDisord: "TLS-запись + disorder",
	StratTor:          "Через Tor",
}

func validStrategy(s string) bool { _, ok := StratNames[s]; return ok }

// findSNI возвращает смещение и длину имени сервера в TLS ClientHello.
func findSNI(b []byte) (off, n int, ok bool) {
	// Запись: тип(1)=0x16, версия(2), длина(2); рукопожатие: тип(1)=1, длина(3)
	if len(b) < 5+4+2+32+1 || b[0] != 0x16 || b[5] != 0x01 {
		return 0, 0, false
	}
	p := 5 + 4 + 2 + 32
	need := func(k int) bool { return p+k <= len(b) }
	if !need(1) {
		return
	}
	p += 1 + int(b[p]) // session id
	if !need(2) {
		return
	}
	p += 2 + int(binary.BigEndian.Uint16(b[p:])) // cipher suites
	if !need(1) {
		return
	}
	p += 1 + int(b[p]) // compression
	if !need(2) {
		return
	}
	end := p + 2 + int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	if end > len(b) {
		end = len(b)
	}
	for p+4 <= end {
		typ := binary.BigEndian.Uint16(b[p:])
		l := int(binary.BigEndian.Uint16(b[p+2:]))
		p += 4
		if typ == 0 { // server_name: list_len(2) type(1) name_len(2) name
			if p+5 > len(b) {
				return 0, 0, false
			}
			nl := int(binary.BigEndian.Uint16(b[p+3:]))
			if p+5+nl > len(b) {
				return 0, 0, false
			}
			return p + 5, nl, true
		}
		p += l
	}
	return 0, 0, false
}

// splitPoint — точка разреза: середина SNI, иначе фиксированное смещение.
func splitPoint(b []byte) int {
	if off, n, ok := findSNI(b); ok && n > 1 {
		return off + n/2
	}
	if len(b) > 1 && b[0] != 0x16 {
		if i := hostHeaderIndex(b); i > 0 {
			return i + 2 // разрез внутри заголовка Host
		}
	}
	if len(b) > 3 {
		return 3
	}
	return len(b) / 2
}

func hostHeaderIndex(b []byte) int {
	return strings.Index(strings.ToLower(string(b[:minInt(len(b), 4096)])), "\r\nhost:")
}

// tlsRecordSplit делит первую TLS-запись на две корректные записи по точке at.
func tlsRecordSplit(b []byte, at int) []byte {
	if len(b) < 6 || b[0] != 0x16 {
		return b
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if 5+recLen > len(b) {
		return b
	}
	k := at - 5 // смещение внутри полезной нагрузки
	if k <= 0 || k >= recLen {
		k = recLen / 2
	}
	payload := b[5 : 5+recLen]
	out := make([]byte, 0, len(b)+5)
	out = append(out, 0x16, b[1], b[2], byte(k>>8), byte(k))
	out = append(out, payload[:k]...)
	out = append(out, 0x16, b[1], b[2], byte((recLen-k)>>8), byte(recLen-k))
	out = append(out, payload[k:]...)
	return append(out, b[5+recLen:]...)
}

// SendFirst отправляет первые байты соединения выбранным методом.
func SendFirst(c net.Conn, data []byte, strat string) error {
	tcp, _ := c.(*net.TCPConn)
	if tcp != nil {
		_ = tcp.SetNoDelay(true)
	}
	at := splitPoint(data)
	useRec := strings.HasPrefix(strat, "tlsrec") && data[0] == 0x16
	if useRec {
		data = tlsRecordSplit(data, at)
		// Новый заголовок записи вставлен ровно в точке at, поэтому TCP-разрез
		// по тому же смещению отделяет первую запись от второй.
		at = 5 + int(binary.BigEndian.Uint16(data[3:5]))
	}
	if at <= 0 || at >= len(data) {
		at = minInt(3, len(data)-1)
	}
	switch {
	case strat == StratNone || strat == StratTLSRec:
		_, err := c.Write(data)
		return err
	case strings.HasSuffix(strat, "split"):
		if _, err := c.Write(data[:at]); err != nil {
			return err
		}
		time.Sleep(5 * time.Millisecond)
		_, err := c.Write(data[at:])
		return err
	case strings.HasSuffix(strat, "disorder"):
		if tcp == nil {
			return errors.New("disorder требует TCP")
		}
		def := defaultTTL(tcp)
		if err := setTTL(tcp, 1); err != nil {
			return err
		}
		if _, err := c.Write(data[:at]); err != nil {
			return err
		}
		time.Sleep(5 * time.Millisecond)
		if err := setTTL(tcp, def); err != nil {
			return err
		}
		_, err := c.Write(data[at:])
		return err
	}
	return errors.New("неизвестный метод: " + strat)
}

// desyncConn применяет метод к первой записи — используется для DoH-клиента.
type desyncConn struct {
	net.Conn
	strat string
	sent  bool
}

func (d *desyncConn) Write(b []byte) (int, error) {
	if d.sent || len(b) == 0 {
		return d.Conn.Write(b)
	}
	d.sent = true
	if err := SendFirst(d.Conn, b, d.strat); err != nil {
		return 0, err
	}
	return len(b), nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
