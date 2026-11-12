package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DoH-серверы указаны по IP, поэтому для них самих DNS не нужен.
// Сертификаты этих серверов содержат их IP-адреса, поэтому проверка TLS проходит без имени.
var DoHServers = map[string]string{
	"cloudflare":  "https://1.1.1.1/dns-query",
	"google":      "https://8.8.8.8/dns-query",
	"quad9":       "https://9.9.9.9/dns-query",
	"cloudflare2": "https://1.0.0.1/dns-query",
	"google2":     "https://8.8.4.4/dns-query",
	"quad9b":      "https://149.112.112.112/dns-query",
}

var dohOrder = []string{"cloudflare", "google", "quad9", "cloudflare2", "google2", "quad9b"}

type cacheEntry struct {
	ips []net.IP
	exp time.Time
}

// Resolver — DNS-over-HTTPS с кэшем. Провайдер не видит запросы и не может подменить ответ.
type Resolver struct {
	mu        sync.Mutex
	cache     map[string]cacheEntry
	preferred string
	client    *http.Client
	// Override — для тестов: фиксированные адреса доменов.
	Override map[string][]net.IP
	logf     func(string, ...any)
}

func NewResolver(preferred string, logf func(string, ...any)) *Resolver {
	r := &Resolver{cache: map[string]cacheEntry{}, preferred: preferred, logf: logf}
	tr := &http.Transport{
		Proxy: nil, // DoH идёт напрямую, но с обходом DPI
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &desyncConn{Conn: c, strat: StratTLSRec}, nil
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        4,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 6 * time.Second,
	}
	r.client = &http.Client{Transport: tr, Timeout: 8 * time.Second}
	return r
}

func (r *Resolver) SetPreferred(p string) {
	r.mu.Lock()
	r.preferred = p
	r.mu.Unlock()
}

// Lookup возвращает IP-адреса домена (сначала IPv4).
func (r *Resolver) Lookup(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if r.Override != nil {
		if ips, ok := r.Override[host]; ok {
			return ips, nil
		}
	}
	if host == "localhost" {
		return []net.IP{net.IPv4(127, 0, 0, 1)}, nil
	}
	r.mu.Lock()
	if e, ok := r.cache[host]; ok && time.Now().Before(e.exp) {
		r.mu.Unlock()
		return e.ips, nil
	}
	order := []string{r.preferred}
	r.mu.Unlock()
	for _, k := range dohOrder {
		if k != order[0] {
			order = append(order, k)
		}
	}

	var lastErr error
	for _, srv := range order {
		url, ok := DoHServers[srv]
		if !ok {
			continue
		}
		ips4, ttl, err := r.query(ctx, url, host, 1)
		if err != nil {
			lastErr = err
			continue
		}
		ips6, _, _ := r.query(ctx, url, host, 28)
		ips := append(ips4, ips6...)
		if len(ips) == 0 {
			return nil, fmt.Errorf("домен %s не найден", host)
		}
		if ttl < 60 {
			ttl = 60
		}
		r.mu.Lock()
		r.cache[host] = cacheEntry{ips, time.Now().Add(time.Duration(ttl) * time.Second)}
		r.mu.Unlock()
		return ips, nil
	}
	// Запасной вариант — системный DNS (может быть подменён провайдером).
	if r.logf != nil {
		r.logf("DoH недоступен (%v), использую системный DNS для %s", lastErr, host)
	}
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("не удалось узнать адрес %s: зашифрованный DNS недоступен, системный DNS не ответил", host)
	}
	return addrs, nil
}

func (r *Resolver) query(ctx context.Context, url, host string, qtype uint16) ([]net.IP, uint32, error) {
	msg, err := buildQuery(host, qtype)
	if err != nil {
		return nil, 0, err
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(msg))
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, 0, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, 0, err
	}
	return parseAnswer(body, qtype)
}

func buildQuery(host string, qtype uint16) ([]byte, error) {
	var b bytes.Buffer
	id := make([]byte, 2)
	_, _ = rand.Read(id)
	b.Write(id)
	b.Write([]byte{0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}) // RD=1, QDCOUNT=1
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, errors.New("некорректное имя домена")
		}
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)
	_ = binary.Write(&b, binary.BigEndian, qtype)
	b.Write([]byte{0, 1}) // IN
	return b.Bytes(), nil
}

func skipName(m []byte, p int) (int, error) {
	for steps := 0; steps < 128; steps++ {
		if p >= len(m) {
			return 0, errors.New("обрезанный ответ DNS")
		}
		l := int(m[p])
		switch {
		case l == 0:
			return p + 1, nil
		case l&0xC0 == 0xC0:
			return p + 2, nil
		default:
			p += 1 + l
		}
	}
	return 0, errors.New("слишком длинное имя")
}

func parseAnswer(m []byte, qtype uint16) ([]net.IP, uint32, error) {
	if len(m) < 12 {
		return nil, 0, errors.New("короткий ответ DNS")
	}
	if rcode := m[3] & 0x0F; rcode != 0 && rcode != 3 {
		return nil, 0, fmt.Errorf("DNS rcode %d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(m[4:]))
	an := int(binary.BigEndian.Uint16(m[6:]))
	p := 12
	var err error
	for i := 0; i < qd; i++ {
		if p, err = skipName(m, p); err != nil {
			return nil, 0, err
		}
		p += 4
	}
	var ips []net.IP
	var minTTL uint32 = 3600
	for i := 0; i < an; i++ {
		if p, err = skipName(m, p); err != nil {
			return nil, 0, err
		}
		if p+10 > len(m) {
			return nil, 0, errors.New("обрезанный ответ DNS")
		}
		typ := binary.BigEndian.Uint16(m[p:])
		ttl := binary.BigEndian.Uint32(m[p+4:])
		rdl := int(binary.BigEndian.Uint16(m[p+8:]))
		p += 10
		if p+rdl > len(m) {
			return nil, 0, errors.New("обрезанный ответ DNS")
		}
		if typ == qtype && ((typ == 1 && rdl == 4) || (typ == 28 && rdl == 16)) {
			ips = append(ips, net.IP(append([]byte(nil), m[p:p+rdl]...)))
			if ttl < minTTL {
				minTTL = ttl
			}
		}
		p += rdl
	}
	return ips, minTTL, nil
}
