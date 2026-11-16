package main

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
)

func dnsQuery(name string, qtype uint16) []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range splitDots(name) {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0)
	q = binary.BigEndian.AppendUint16(q, qtype)
	return binary.BigEndian.AppendUint16(q, 1)
}

func splitDots(s string) []string {
	var out []string
	st := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			out = append(out, s[st:i])
			st = i + 1
		}
	}
	return out
}

func TestAnswerDNS(t *testing.T) {
	r := NewResolver("cloudflare", t.Logf)
	r.Override = map[string][]net.IP{"example.com": {net.IPv4(93, 184, 216, 34)}}
	e := NewEngine(r, t.Logf)
	e.Ads = NewAdBlock(t.TempDir(), nil)
	_ = context.Background

	resp := e.answerDNS(dnsQuery("Example.COM", dnsTypeA))
	if resp == nil || resp[0] != 0x12 || resp[2]&0x80 == 0 || resp[3]&0x0F != 0 {
		t.Fatalf("ответ: %x", resp)
	}
	if an := binary.BigEndian.Uint16(resp[6:8]); an != 1 {
		t.Fatalf("ответов %d", an)
	}
	if got := net.IP(resp[len(resp)-4:]).String(); got != "93.184.216.34" {
		t.Fatalf("адрес %s", got)
	}
	if h := e.hostFor("93.184.216.34"); h != "example.com" {
		t.Fatalf("имя по адресу: %q", h)
	}
	// реклама — 0.0.0.0
	resp = e.answerDNS(dnsQuery("ads.doubleclick.net", dnsTypeA))
	if got := net.IP(resp[len(resp)-4:]).String(); got != "0.0.0.0" {
		t.Fatalf("реклама: %s", got)
	}
	// AAAA — пусто, местные имена — NXDOMAIN
	resp = e.answerDNS(dnsQuery("example.com", dnsTypeAAAA))
	if binary.BigEndian.Uint16(resp[6:8]) != 0 || resp[3]&0x0F != 0 {
		t.Fatalf("AAAA: %x", resp)
	}
	resp = e.answerDNS(dnsQuery("printer.local", dnsTypeA))
	if resp[3]&0x0F != 3 {
		t.Fatalf("local: %x", resp)
	}
	if e.answerDNS([]byte{1, 2, 3}) != nil {
		t.Fatal("мусор должен игнорироваться")
	}
}
