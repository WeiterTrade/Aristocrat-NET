package main

// DNS для устройств (Android): запросы на порт 53 приходят в ядро через SOCKS5 UDP,
// ядро отвечает НАСТОЯЩИМИ адресами (через шифрованный DNS, без подмены провайдером)
// и запоминает, какому имени принадлежит адрес. Когда приложение потом подключается
// по адресу, ядро узнаёт имя сайта — и для него работают обход DPI, правила и блокировка рекламы.
//
// Раньше VPN отдавал «ненастоящие» адреса (mapdns, 100.64.x.x). Устройства, подключённые
// к телефону по точке доступа, получали эти адреса и не могли по ним никуда подключиться —
// интернет на раздаче пропадал. С настоящими адресами раздача работает.

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"
)

type dnsNames struct {
	mu sync.Mutex
	m  map[string]dnsName
}

type dnsName struct {
	host string
	exp  time.Time
}

func (d *dnsNames) put(ip net.IP, host string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.m == nil || len(d.m) > 50000 {
		d.m = map[string]dnsName{}
	}
	d.m[ip.String()] = dnsName{host, time.Now().Add(6 * time.Hour)}
}

// name — имя сайта, которое недавно разрешилось в этот адрес ("" — неизвестно).
func (d *dnsNames) name(ip string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if v, ok := d.m[ip]; ok && time.Now().Before(v.exp) {
		return v.host
	}
	return ""
}

const (
	dnsTypeA    = 1
	dnsTypeAAAA = 28
)

// parseDNSQuery — имя и тип первого вопроса; qEnd — конец раздела вопроса.
func parseDNSQuery(q []byte) (name string, qtype uint16, qEnd int, ok bool) {
	if len(q) < 12 || q[2]&0x80 != 0 || binary.BigEndian.Uint16(q[4:6]) < 1 {
		return "", 0, 0, false
	}
	i := 12
	var labels []string
	for {
		if i >= len(q) {
			return "", 0, 0, false
		}
		l := int(q[i])
		if l == 0 {
			i++
			break
		}
		if l&0xC0 != 0 || i+1+l > len(q) || len(labels) > 127 {
			return "", 0, 0, false
		}
		labels = append(labels, string(q[i+1:i+1+l]))
		i += 1 + l
	}
	if i+4 > len(q) {
		return "", 0, 0, false
	}
	return strings.ToLower(strings.Join(labels, ".")), binary.BigEndian.Uint16(q[i : i+2]), i + 4, true
}

// buildDNSReply — ответ на запрос q: адреса ips (rcode 0) или код ошибки.
func buildDNSReply(q []byte, qEnd int, rcode byte, ips []net.IP, qtype uint16) []byte {
	out := make([]byte, 0, qEnd+16*len(ips))
	out = append(out, q[:qEnd]...)
	out[2] = 0x80 | (q[2] & 0x79)  // QR, тот же opcode и RD
	out[3] = 0x80 | (rcode & 0x0F) // RA
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], 0)
	n := 0
	for _, ip := range ips {
		var rd []byte
		if qtype == dnsTypeA {
			rd = ip.To4()
		} else if qtype == dnsTypeAAAA && ip.To4() == nil {
			rd = ip.To16()
		}
		if rd == nil {
			continue
		}
		out = append(out, 0xC0, 0x0C) // имя — ссылка на вопрос
		out = binary.BigEndian.AppendUint16(out, qtype)
		out = binary.BigEndian.AppendUint16(out, 1)  // IN
		out = binary.BigEndian.AppendUint32(out, 60) // TTL
		out = binary.BigEndian.AppendUint16(out, uint16(len(rd)))
		out = append(out, rd...)
		n++
	}
	binary.BigEndian.PutUint16(out[6:8], uint16(n))
	return out
}

// answerDNS отвечает на DNS-запрос устройства.
func (e *Engine) answerDNS(q []byte) []byte {
	name, qtype, qEnd, ok := parseDNSQuery(q)
	if !ok {
		return nil
	}
	if name == "" || !strings.Contains(name, ".") || strings.HasSuffix(name, ".local") || strings.HasSuffix(name, ".arpa") {
		return buildDNSReply(q, qEnd, 3, nil, qtype) // NXDOMAIN: местные имена тут не разрешить
	}
	if qtype != dnsTypeA && qtype != dnsTypeAAAA {
		return buildDNSReply(q, qEnd, 0, nil, qtype) // HTTPS, SVCB и прочее — пусто
	}
	if e.Ads.Blocked(name) {
		if qtype == dnsTypeA {
			return buildDNSReply(q, qEnd, 0, []net.IP{net.IPv4zero}, qtype)
		}
		return buildDNSReply(q, qEnd, 0, nil, qtype)
	}
	if qtype == dnsTypeAAAA {
		return buildDNSReply(q, qEnd, 0, nil, qtype) // только IPv4: так все соединения идут через ядро
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	ips, err := e.Resolver.Lookup(ctx, name)
	if err != nil {
		return buildDNSReply(q, qEnd, 2, nil, qtype) // SERVFAIL
	}
	var v4 []net.IP
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			v4 = append(v4, ip4)
			e.names.put(ip4, name)
		}
	}
	return buildDNSReply(q, qEnd, 0, v4, qtype)
}

// hostFor — имя сайта для адреса, к которому подключается приложение (если известно).
func (e *Engine) hostFor(host string) string {
	if net.ParseIP(host) == nil {
		return host
	}
	if n := e.names.name(host); n != "" {
		return n
	}
	return host
}
