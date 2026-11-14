package main

// Проверка своих мостов Tor перед запуском.
//
// Tor выбирает «входной» мост почти случайно и долго ждёт заблокированные. Поэтому перед
// запуском программа сама пробует соединиться с каждым своим мостом (как ping, но по TCP):
// недоступные убирает, а быстрые ставит первыми и оставляет несколько лучших.
// Через самый быстрый мост Tor и подключается быстрее, и работает быстрее.

import (
	"context"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxBridges = 5 // столько лучших своих мостов передаётся Tor

// bridgeTarget — адрес, по которому можно проверить мост ("" — проверить нельзя: snowflake, meek).
func bridgeTarget(line string) string {
	f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "Bridge "))
	if len(f) == 0 {
		return ""
	}
	transport, addr := "", f[0]
	if !looksLikeAddr(f[0]) {
		transport = f[0]
		if len(f) < 2 {
			return ""
		}
		addr = f[1]
	}
	switch transport {
	case "snowflake", "meek_lite", "meek", "conjure":
		return "" // идут через посредников (CDN, брокер) — адрес в строке условный
	case "webtunnel":
		// Адрес в строке условный, настоящий — в url=.
		for _, kv := range f {
			if u, ok := strings.CutPrefix(kv, "url="); ok {
				if pu, err := url.Parse(u); err == nil && pu.Hostname() != "" {
					port := pu.Port()
					if port == "" {
						port = "443"
						if pu.Scheme == "http" {
							port = "80"
						}
					}
					return net.JoinHostPort(pu.Hostname(), port)
				}
			}
		}
		return ""
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return ""
	}
	return addr
}

// rankBridges проверяет свои мосты и возвращает их заново: сначала доступные по скорости
// (не больше maxBridges), затем непроверяемые (snowflake, meek). Если не ответил ни один —
// возвращает все как есть: возможно, проверке мешает что-то другое, пусть решает сам Tor.
// dial — соединение с адресом host:port (nil — обычное).
func rankBridges(custom string, dial func(ctx context.Context, addr string) (net.Conn, error), logf func(string, ...any)) string {
	type res struct {
		line string
		rtt  time.Duration
		ok   bool
		test bool
	}
	var list []*res
	for _, l := range strings.Split(custom, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		list = append(list, &res{line: l})
	}
	if len(list) == 0 {
		return custom
	}
	if dial == nil {
		dial = func(ctx context.Context, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		}
	}
	var wg sync.WaitGroup
	for _, r := range list {
		target := bridgeTarget(r.line)
		if target == "" {
			continue
		}
		r.test = true
		wg.Add(1)
		go func(r *res, target string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			start := time.Now()
			c, err := dial(ctx, target)
			if err == nil {
				r.rtt, r.ok = time.Since(start), true
				c.Close()
			}
		}(r, target)
	}
	wg.Wait()

	var good, untested []*res
	tested, okN := 0, 0
	for _, r := range list {
		switch {
		case !r.test:
			untested = append(untested, r)
		case r.ok:
			tested++
			okN++
			good = append(good, r)
		default:
			tested++
		}
	}
	if tested == 0 {
		return custom
	}
	if len(good) == 0 {
		logf("Tor: ни один из своих мостов не ответил на проверку — передаю Tor все (%d)", tested)
		return custom
	}
	sort.SliceStable(good, func(i, j int) bool { return good[i].rtt < good[j].rtt })
	if len(good) > maxBridges {
		good = good[:maxBridges]
	}
	var b strings.Builder
	for _, r := range append(good, untested...) {
		b.WriteString(r.line)
		b.WriteByte('\n')
	}
	logf("Tor: свои мосты проверены — доступно %d из %d, самый быстрый отвечает за %s",
		okN, tested, fmtMs(good[0].rtt))
	return b.String()
}

func fmtMs(d time.Duration) string { return strconv.Itoa(int(d.Milliseconds())) + " мс" }
