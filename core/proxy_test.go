package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- Имитация DPI (ТСПУ) ---------------------------------------------------
// mode "packet":   смотрит только первый TCP-сегмент и первую TLS-запись (как простые DPI)
// mode "reasm":    собирает сегменты до конца первой записи, но не склеивает записи
// mode "records":  склеивает TLS-записи, но смотрит только первый сегмент
type dpiSim struct {
	mode     string
	blocked  string
	upstream string
	resets   atomic.Int64
	ln       net.Listener
}

func sniOf(b []byte) string {
	if off, n, ok := findSNI(b); ok {
		return string(b[off : off+n])
	}
	return ""
}

// joinRecords склеивает подряд идущие handshake-записи в одну (как «умный» DPI).
func joinRecords(b []byte) []byte {
	var payload []byte
	p := 0
	for p+5 <= len(b) && b[p] == 0x16 {
		l := int(binary.BigEndian.Uint16(b[p+3:]))
		end := p + 5 + l
		if end > len(b) {
			end = len(b)
		}
		payload = append(payload, b[p+5:end]...)
		p = end
	}
	if len(payload) == 0 {
		return b
	}
	return append([]byte{0x16, b[1], b[2], byte(len(payload) >> 8), byte(len(payload))}, payload...)
}

func (d *dpiSim) inspect(c net.Conn) ([]byte, bool) {
	buf := make([]byte, 64*1024)
	n, err := c.Read(buf)
	if err != nil {
		return nil, false
	}
	data := buf[:n]
	view := data
	switch d.mode {
	case "packet":
		if len(view) >= 5 && view[0] == 0x16 {
			if l := 5 + int(binary.BigEndian.Uint16(view[3:5])); l < len(view) {
				view = view[:l]
			}
		}
	case "reasm":
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		for len(data) >= 5 && data[0] == 0x16 && len(data) < 5+int(binary.BigEndian.Uint16(data[3:5])) {
			m, err := c.Read(buf)
			if err != nil {
				break
			}
			data = append(data, buf[:m]...)
		}
		_ = c.SetReadDeadline(time.Time{})
		view = data
		if l := 5 + int(binary.BigEndian.Uint16(view[3:5])); l < len(view) {
			view = view[:l]
		}
	case "records":
		view = joinRecords(data)
	}
	// Простая проверка «как у DPI»: полное имя в разобранном ClientHello или в заголовке Host.
	if sniOf(view) == d.blocked || bytes.Contains(bytes.ToLower(view), []byte("host: "+d.blocked)) {
		return data, true
	}
	return data, false
}

func (d *dpiSim) serve(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d.ln = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				first, block := d.inspect(c)
				if block {
					d.resets.Add(1)
					_ = c.(*net.TCPConn).SetLinger(0) // RST, как у ТСПУ
					return
				}
				up, err := net.Dial("tcp", d.upstream)
				if err != nil {
					return
				}
				defer up.Close()
				_, _ = up.Write(first)
				go func() { _, _ = io.Copy(up, c) }()
				_, _ = io.Copy(c, up)
			}(c)
		}
	}()
}

func newTestEngine(t *testing.T, port int) *Engine {
	r := NewResolver("cloudflare", t.Logf)
	r.Override = map[string][]net.IP{"blocked.test": {net.IPv4(127, 0, 0, 1)}}
	e := NewEngine(r, t.Logf)
	e.Timeout = 1500 * time.Millisecond
	if err := e.Start(port); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)
	return e
}

func freePort(t *testing.T) int {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func httpsVia(t *testing.T, proxyPort int, target string) (string, error) {
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
	cl := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		Proxy:           http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
	resp, err := cl.Get(target)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

func TestBypassAgainstDPI(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "OK:"+r.Host)
	}))
	defer srv.Close()
	upstream := strings.TrimPrefix(srv.URL, "https://")

	cases := []struct {
		mode string
		want []string // какие методы должны пройти
	}{
		{"packet", []string{StratTLSRec, StratSplit}},
		{"reasm", []string{StratTLSRec}},
		{"records", []string{StratSplit, StratDisorder}},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			sim := &dpiSim{mode: tc.mode, blocked: "blocked.test", upstream: upstream}
			sim.serve(t)
			defer sim.ln.Close()
			simPort := sim.ln.Addr().(*net.TCPAddr).Port
			target := fmt.Sprintf("https://blocked.test:%d/", simPort)

			// 1) без обхода сайт блокируется
			raw, _ := net.Dial("tcp", sim.ln.Addr().String())
			tcl := tls.Client(raw, &tls.Config{ServerName: "blocked.test", InsecureSkipVerify: true})
			if err := tcl.Handshake(); err == nil {
				t.Fatal("DPI-симулятор пропустил соединение без обхода")
			}
			raw.Close()

			// 2) через прокси в авторежиме сайт открывается
			port := freePort(t)
			e := newTestEngine(t, port)
			body, err := httpsVia(t, port, target)
			if err != nil || body != fmt.Sprintf("OK:blocked.test:%d", simPort) {
				t.Fatalf("через прокси: %q, %v", body, err)
			}
			learned := e.Learned()["blocked.test"]
			t.Logf("режим DPI %q: подобран метод %q, сбросов DPI: %d", tc.mode, learned, sim.resets.Load())
			ok := learned == "" && tc.want[0] == StratTLSRec
			for _, w := range tc.want {
				if strings.HasSuffix(learned, w) || learned == w {
					ok = true
				}
			}
			if !ok && !(learned == StratTLSRecSplit || learned == StratTLSRecDisord) {
				t.Errorf("неожиданный метод %q", learned)
			}

			// 3) второй запрос сразу идёт запомненным методом, без новых сбросов
			before := sim.resets.Load()
			if _, err := httpsVia(t, port, target); err != nil {
				t.Fatal(err)
			}
			if sim.resets.Load() != before {
				t.Error("повторный запрос снова упёрся в DPI")
			}

			// 4) «Проверить сайт» показывает, какие методы работают
			res, err := e.TestHost(fmt.Sprintf("blocked.test:%d", simPort), true)
			if err != nil {
				t.Fatal(err)
			}
			var line []string
			for _, r := range res {
				line = append(line, fmt.Sprintf("%s=%v", r.Strategy, r.OK))
				if r.Strategy == StratNone && r.OK {
					t.Error("проверка: «без изменений» не должен проходить DPI")
				}
			}
			t.Log(strings.Join(line, " "))
		})
	}
}

func TestSOCKS5AndPlainHTTP(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "PLAIN:"+r.URL.Path)
	}))
	defer plain.Close()
	sim := &dpiSim{mode: "packet", blocked: "blocked.test", upstream: strings.TrimPrefix(plain.URL, "http://")}
	sim.serve(t)
	defer sim.ln.Close()
	simPort := sim.ln.Addr().(*net.TCPAddr).Port
	port := freePort(t)
	newTestEngine(t, port)

	// обычный HTTP через прокси: заголовок Host разрезается
	pu, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	cl := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	resp, err := cl.Get(fmt.Sprintf("http://blocked.test:%d/abc", simPort))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "PLAIN:/abc" {
		t.Fatalf("http: %q", b)
	}

	// SOCKS5 с доменным именем
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{5, 1, 0})
	r := bufio.NewReader(c)
	hs := make([]byte, 2)
	io.ReadFull(r, hs)
	name := "blocked.test"
	req := append([]byte{5, 1, 0, 3, byte(len(name))}, name...)
	req = binary.BigEndian.AppendUint16(req, uint16(simPort))
	c.Write(req)
	rep := make([]byte, 10)
	io.ReadFull(r, rep)
	if rep[1] != 0 {
		t.Fatal("socks reply", rep)
	}
	fmt.Fprintf(c, "GET /socks HTTP/1.1\r\nHost: blocked.test\r\nConnection: close\r\n\r\n")
	all, _ := io.ReadAll(r)
	if !strings.Contains(string(all), "PLAIN:/socks") {
		t.Fatalf("socks: %q", all)
	}
}

func TestTLSRecordSplitValid(t *testing.T) {
	// Настоящий ClientHello от crypto/tls
	cli, srv := net.Pipe()
	go func() {
		tc := tls.Client(cli, &tls.Config{ServerName: "www.example-blocked-site.com", InsecureSkipVerify: true})
		_ = tc.Handshake()
	}()
	buf := make([]byte, 16*1024)
	n, _ := srv.Read(buf)
	hello := buf[:n]
	srv.Close()
	if sniOf(hello) != "www.example-blocked-site.com" {
		t.Fatal("SNI не найден")
	}
	at := splitPoint(hello)
	out := tlsRecordSplit(hello, at)
	if len(out) != len(hello)+5 {
		t.Fatal("длина")
	}
	if sniOf(out[:5+int(binary.BigEndian.Uint16(out[3:5]))]) != "" {
		t.Fatal("первая запись всё ещё содержит полный SNI")
	}
	if !bytes.Equal(joinRecords(out), hello) {
		t.Fatal("склейка записей не совпадает с оригиналом")
	}
}

func TestDNSParse(t *testing.T) {
	q, err := buildQuery("example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	// ответ: копия запроса + 1 запись A со сжатым именем
	resp := append([]byte(nil), q...)
	resp[2], resp[3] = 0x81, 0x80
	resp[7] = 1
	resp = append(resp, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 1, 0x2C, 0, 4, 93, 184, 216, 34)
	ips, ttl, err := parseAnswer(resp, 1)
	if err != nil || len(ips) != 1 || ips[0].String() != "93.184.216.34" || ttl != 300 {
		t.Fatal(ips, ttl, err)
	}
}
