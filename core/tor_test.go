package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeTor — SOCKS5-сервер, изображающий Tor: соединяет с upstream независимо от адреса.
type fakeTor struct {
	ln       net.Listener
	upstream string
	hits     atomic.Int64
	lastHost atomic.Value
}

func startFakeTor(t *testing.T, upstream string) *fakeTor {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeTor{ln: ln, upstream: upstream}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeTor) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	h := make([]byte, 2)
	if _, err := io.ReadFull(r, h); err != nil {
		return
	}
	io.ReadFull(r, make([]byte, h[1]))
	c.Write([]byte{5, 0})
	req := make([]byte, 4)
	if _, err := io.ReadFull(r, req); err != nil {
		return
	}
	var host string
	switch req[3] {
	case 3:
		l, _ := r.ReadByte()
		n := make([]byte, l)
		io.ReadFull(r, n)
		host = string(n)
	case 1:
		ip := make([]byte, 4)
		io.ReadFull(r, ip)
		host = net.IP(ip).String()
	}
	io.ReadFull(r, make([]byte, 2))
	f.lastHost.Store(host)
	up, err := net.Dial("tcp", f.upstream)
	if err != nil {
		c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	if host != "check.torproject.org" {
		f.hits.Add(1)
	}
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	go func() { io.Copy(up, r) }()
	io.Copy(c, up)
}

func engineWithTor(t *testing.T, override map[string][]net.IP, torAddr string) (*Engine, int) {
	r := NewResolver("cloudflare", t.Logf)
	r.Override = override
	e := NewEngine(r, t.Logf)
	e.Timeout = 800 * time.Millisecond
	e.DialTimeout = 800 * time.Millisecond
	e.TorWait = 5 * time.Second
	tor := NewTor(t.Logf)
	tor.UseExternal(torAddr)
	if !tor.WaitReady(8 * time.Second) {
		t.Fatal("фейковый Tor не стал готов")
	}
	t.Cleanup(tor.Stop)
	e.Tor = tor
	port := freePort(t)
	if err := e.Start(port); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)
	return e, port
}

// Сайт заблокирован по IP: TCP-соединение невозможно → автоматически через Tor.
func TestTorFallbackOnIPBlock(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "VIA-TOR") }))
	defer srv.Close()
	ft := startFakeTor(t, strings.TrimPrefix(srv.URL, "https://"))
	// «Заблокированный» адрес — закрытый порт: соединение сразу отклоняется.
	dead := freePort(t)
	e, port := engineWithTor(t, map[string][]net.IP{"ipblocked.test": {net.IPv4(127, 0, 0, 1)}}, ft.ln.Addr().String())

	body, err := httpsVia(t, port, fmt.Sprintf("https://ipblocked.test:%d/", dead))
	if err != nil || body != "VIA-TOR" {
		t.Fatalf("%q %v", body, err)
	}
	if got := e.Learned()["ipblocked.test"]; got != StratTor {
		t.Fatalf("ожидался запомненный маршрут tor, получено %q", got)
	}
	if h, _ := ft.lastHost.Load().(string); h != "ipblocked.test" {
		t.Fatalf("в Tor должно уходить имя домена, а не IP: %q", h)
	}
	// Второй раз — сразу через Tor.
	before := ft.hits.Load()
	if _, err := httpsVia(t, port, fmt.Sprintf("https://ipblocked.test:%d/", dead)); err != nil {
		t.Fatal(err)
	}
	if ft.hits.Load() != before+1 {
		t.Fatal("повторный запрос не пошёл через Tor")
	}
}

// DPI режет все варианты ClientHello → после перебора методов — Tor, с теми же первыми байтами.
func TestTorFallbackOnDPI(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "VIA-TOR-2") }))
	defer srv.Close()
	ft := startFakeTor(t, strings.TrimPrefix(srv.URL, "https://"))
	// «Жёсткий» DPI: сбрасывает любое TLS-соединение.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 4096)
				c.Read(buf)
				c.(*net.TCPConn).SetLinger(0)
				c.Close()
			}(c)
		}
	}()
	e, port := engineWithTor(t, map[string][]net.IP{"hard.test": {net.IPv4(127, 0, 0, 1)}}, ft.ln.Addr().String())
	body, err := httpsVia(t, port, fmt.Sprintf("https://hard.test:%d/", ln.Addr().(*net.TCPAddr).Port))
	if err != nil || body != "VIA-TOR-2" {
		t.Fatalf("%q %v", body, err)
	}
	if got := e.Learned()["hard.test"]; got != StratTor {
		t.Fatalf("learned=%q", got)
	}

	// «Проверить сайт» показывает строку Tor.
	res, err := e.TestHost(fmt.Sprintf("hard.test:%d", ln.Addr().(*net.TCPAddr).Port), true)
	if err != nil {
		t.Fatal(err)
	}
	var torOK, directOK bool
	for _, r := range res {
		if r.Strategy == StratTor {
			torOK = r.OK
		} else if r.OK {
			directOK = true
		}
	}
	if !torOK || directOK {
		t.Fatalf("проверка: tor=%v direct=%v %+v", torOK, directOK, res)
	}
}

// Режим «Только DPI» никогда не использует Tor; «Всё через Tor» — всегда.
func TestRouteModes(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "OK") }))
	defer srv.Close()
	up := strings.TrimPrefix(srv.URL, "https://")
	ft := startFakeTor(t, up)
	dead := freePort(t)
	e, port := engineWithTor(t, map[string][]net.IP{"x.test": {net.IPv4(127, 0, 0, 1)}}, ft.ln.Addr().String())

	e.Route.Store(RouteDPI)
	if _, err := httpsVia(t, port, fmt.Sprintf("https://x.test:%d/", dead)); err == nil {
		t.Fatal("в режиме «Только DPI» запрос не должен был пройти через Tor")
	}
	e.Route.Store(RouteTor)
	before := ft.hits.Load()
	_, upPort, _ := net.SplitHostPort(up)
	if _, err := httpsVia(t, port, "https://x.test:"+upPort+"/"); err != nil {
		t.Fatal(err)
	}
	if ft.hits.Load() != before+1 {
		t.Fatal("в режиме «Всё через Tor» запрос пошёл мимо Tor")
	}
}

const samplePT = `{
  "recommendedDefault": "obfs4",
  "pluggableTransports": {
    "lyrebird": "ClientTransportPlugin meek_lite,obfs2,obfs3,obfs4,scramblesuit,webtunnel exec ${pt_path}lyrebird",
    "snowflake": "ClientTransportPlugin snowflake exec ${pt_path}lyrebird",
    "conjure": "ClientTransportPlugin conjure exec ${pt_path}conjure-client -registerURL https://registration.refraction.network/api"
  },
  "bridges": {
    "obfs4": ["obfs4 192.0.2.1:443 AAAA cert=xyz iat-mode=0", "obfs4 192.0.2.2:80 BBBB cert=abc iat-mode=0"],
    "snowflake": ["snowflake 192.0.2.3:80 2B28 fingerprint=2B28 url=https://snowflake-broker.example/ fronts=foo.example ice=stun:stun.example:3478"],
    "meek-azure": ["meek_lite 192.0.2.18:80 BE77 url=https://meek.example/ front=ajax.example"]
  }
}`

func TestBuildTorrc(t *testing.T) {
	dir := t.TempDir()
	ptPath := filepath.Join(dir, "pt_config.json")
	os.WriteFile(ptPath, []byte(samplePT), 0o600)

	// ПК, snowflake: только нужный транспорт, относительный путь без пробелов.
	rc, err := BuildTorrc(TorOptions{Bridges: "snowflake", SocksAddr: torSocksAddr, DataDir: "/data dir",
		PTConfigPath: ptPath, PTDir: "pt"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"SOCKSPort 127.0.0.1:9077", "DataDirectory /data dir", "UseBridges 1",
		"ClientTransportPlugin snowflake exec pt" + string(filepath.Separator) + "lyrebird", "Bridge snowflake 192.0.2.3:80"} {
		if !strings.Contains(rc, want) {
			t.Errorf("нет строки %q в\n%s", want, rc)
		}
	}
	if strings.Contains(rc, "obfs4 192.0.2.1") || strings.Contains(rc, "conjure") {
		t.Errorf("лишние мосты/транспорты:\n%s", rc)
	}

	// Android: путь к liblyrebird.so, без DataDirectory.
	rc, err = BuildTorrc(TorOptions{Bridges: "obfs4", SocksAddr: torSocksAddr, PTConfigPath: ptPath,
		LyrebirdPath: "/data/app/x/lib/arm64/liblyrebird.so", ForAndroid: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rc, "exec /data/app/x/lib/arm64/liblyrebird.so") || strings.Contains(rc, "DataDirectory") ||
		strings.Count(rc, "Bridge obfs4") != 2 {
		t.Errorf("android torrc:\n%s", rc)
	}

	// Свои мосты (строки из @GetBridgesBot), meek через meek-azure, без мостов.
	rc, err = BuildTorrc(TorOptions{Bridges: "custom", Custom: "Bridge webtunnel [2001:db8::1]:443 FP url=https://x.example/abc ver=0.0.1\n\n# comment\n",
		SocksAddr: torSocksAddr, PTConfigPath: ptPath, PTDir: "pt"})
	if err != nil || !strings.Contains(rc, "Bridge webtunnel [2001:db8::1]:443") || !strings.Contains(rc, "webtunnel exec") {
		t.Errorf("custom: %v\n%s", err, rc)
	}
	if rc, err = BuildTorrc(TorOptions{Bridges: "meek", SocksAddr: torSocksAddr, PTConfigPath: ptPath, PTDir: "pt"}); err != nil || !strings.Contains(rc, "Bridge meek_lite") {
		t.Errorf("meek: %v\n%s", err, rc)
	}
	if rc, err = BuildTorrc(TorOptions{Bridges: "none", SocksAddr: torSocksAddr}); err != nil || strings.Contains(rc, "UseBridges") {
		t.Errorf("none: %v\n%s", err, rc)
	}
	if _, err = BuildTorrc(TorOptions{Bridges: "custom", Custom: "  ", SocksAddr: torSocksAddr}); err == nil {
		t.Error("пустые свои мосты должны давать ошибку")
	}
}

var _ = binary.BigEndian

// Android: snowflake из старого pt_config (отдельный snowflake-client) должен идти через наш liblyrebird.so,
// а webtunnel без встроенных мостов — давать понятную ошибку, а не падение tor.
func TestAndroidTorrcPaths(t *testing.T) {
	dir := t.TempDir()
	ptPath := filepath.Join(dir, "pt_config.json")
	old := strings.Replace(samplePT, `"ClientTransportPlugin snowflake exec ${pt_path}lyrebird"`,
		`"ClientTransportPlugin snowflake exec ${pt_path}snowflake-client -url https://x/ -log snow.log"`, 1)
	os.WriteFile(ptPath, []byte(old), 0o600)
	lyre := "/data/app/org.obhod.app/lib/arm/liblyrebird.so"
	rc, err := BuildTorrc(TorOptions{Bridges: "snowflake", SocksAddr: torSocksAddr, PTConfigPath: ptPath,
		LyrebirdPath: lyre, ForAndroid: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rc, "ClientTransportPlugin snowflake exec "+lyre+"\n") || strings.Contains(rc, "snowflake-client") {
		t.Fatalf("snowflake должен запускаться через liblyrebird.so:\n%s", rc)
	}
	if _, err := BuildTorrc(TorOptions{Bridges: "webtunnel", SocksAddr: torSocksAddr, PTConfigPath: ptPath,
		LyrebirdPath: lyre, ForAndroid: true}); err == nil || !strings.Contains(err.Error(), "GetBridgesBot") {
		t.Fatalf("ожидалась подсказка про свои мосты, получено: %v", err)
	}
}

func TestExplainTorExit(t *testing.T) {
	cases := map[string]string{
		"[warn] It looks like another Tor process is running with the same data directory.":        "старая копия tor",
		"[warn] Could not bind to 127.0.0.1:9077: Address already in use. Is Tor already running?": "порт Tor занят",
		"[warn] Managed proxy at 'pt\\lyrebird.exe' failed at launch.":                             "транспорт мостов",
		"[warn] Our clock is 2 hours behind the time published in the consensus":                   "clock",
	}
	for line, want := range cases {
		if got := explainTorExit([]string{line}, nil); !strings.Contains(got, want) {
			t.Errorf("%q → %q, ожидалось %q", line, got, want)
		}
	}
}

func TestAutoBridges(t *testing.T) {
	dir := t.TempDir()
	ptPath := filepath.Join(dir, "pt_config.json")
	os.WriteFile(ptPath, []byte(samplePT), 0o600)
	rc, err := BuildTorrc(TorOptions{Bridges: "auto", Custom: "webtunnel [2001:db8::2]:443 FP url=https://w.example/x ver=0.0.1",
		SocksAddr: torSocksAddr, PTConfigPath: ptPath, PTDir: "pt"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Bridge webtunnel", "Bridge snowflake", "Bridge obfs4 192.0.2.1", "Bridge meek_lite",
		"ClientTransportPlugin snowflake exec", "webtunnel"} {
		if !strings.Contains(rc, want) {
			t.Errorf("нет %q в\n%s", want, rc)
		}
	}
	if strings.Index(rc, "Bridge webtunnel") > strings.Index(rc, "Bridge snowflake") {
		t.Error("свои мосты должны идти первыми")
	}
}
