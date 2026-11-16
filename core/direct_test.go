package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalRules(t *testing.T) {
	dir := t.TempDir()
	geo := filepath.Join(dir, "geoip")
	// 5.0.0.0–5.0.0.255 — Россия, 6.0.0.0–6.0.0.255 — Германия
	os.WriteFile(geo, []byte("# test\n83886080,83886335,RU\n100663296,100663551,DE\n"), 0o600)
	g := &GeoIP{}
	if err := g.Load(geo); err != nil || !g.Loaded() {
		t.Fatal(err)
	}
	if g.Country(net.ParseIP("5.0.0.7")) != "RU" || g.Country(net.ParseIP("6.0.0.1")) != "DE" || g.Country(net.ParseIP("7.0.0.1")) != "" {
		t.Fatal("GeoIP")
	}
	country := "RU"
	l := &Local{Geo: g, Enabled: func() bool { return true }, UserCountry: func() string { return country },
		Resolve: func(ctx context.Context, host string) ([]net.IP, error) {
			if host == "shop.example.com" {
				return []net.IP{net.ParseIP("5.0.0.9")}, nil
			}
			return []net.IP{net.ParseIP("6.0.0.9")}, nil
		}}
	for host, want := range map[string]bool{
		"gosuslugi.ru": true, "online.sberbank.ru": true, "kaspi.kz": true, "xn--80ao21a": true, "yastatic.net": true,
		"vk.com": true, "shop.example.com": true /* сервер в России */, "5.0.0.1": true,
		"youtube.com": false, "6.0.0.1": false, "grus.com": false,
	} {
		if got := l.Direct(host); got != want {
			t.Errorf("Direct(%s) = %v", host, got)
		}
	}
	if !l.NeedsForeignIP("open.spotify.com") || !l.NeedsForeignIP("audio-ak-spotify-com.akamaized.net") || l.NeedsForeignIP("youtube.com") {
		t.Error("Spotify в России")
	}
	country = "KZ"
	if l.NeedsForeignIP("open.spotify.com") {
		t.Error("в Казахстане Spotify через Tor не нужен")
	}
}

// Режим «Всё через Tor»: российский сайт идёт напрямую, а Spotify у пользователя из России — через Tor.
func TestRouteLocalDirectAndSpotify(t *testing.T) {
	direct := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "DIRECT") }))
	defer direct.Close()
	viaTor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "VIA-TOR") }))
	defer viaTor.Close()
	ft := startFakeTor(t, strings.TrimPrefix(viaTor.URL, "https://"))
	_, dport, _ := net.SplitHostPort(strings.TrimPrefix(direct.URL, "https://"))
	e, port := engineWithTor(t, map[string][]net.IP{
		"bank.ru": {net.IPv4(127, 0, 0, 1)}, "open.spotify.com": {net.IPv4(127, 0, 0, 1)}, "site.org": {net.IPv4(127, 0, 0, 1)},
	}, ft.ln.Addr().String())
	e.Route.Store(RouteTor)
	e.Local = &Local{Geo: &GeoIP{}, Enabled: func() bool { return true }, UserCountry: func() string { return "RU" }}

	if body, err := httpsVia(t, port, "https://bank.ru:"+dport+"/"); err != nil || body != "DIRECT" {
		t.Fatalf("bank.ru должен идти напрямую: %q %v", body, err)
	}
	if body, err := httpsVia(t, port, "https://site.org:"+dport+"/"); err != nil || body != "VIA-TOR" {
		t.Fatalf("обычный сайт в режиме Tor — через Tor: %q %v", body, err)
	}
	e.Route.Store(RouteAuto)
	if body, err := httpsVia(t, port, "https://open.spotify.com:"+dport+"/"); err != nil || body != "VIA-TOR" {
		t.Fatalf("Spotify в России — через Tor даже в «Авто»: %q %v", body, err)
	}
}

func TestYouTubeHomeIPInRussia(t *testing.T) {
	cc := "RU"
	l := &Local{UserCountry: func() string { return cc }}
	for h, want := range map[string]bool{"www.youtube.com": true, "rr1---sn-x.googlevideo.com": true, "i.ytimg.com": true,
		"youtu.be": true, "google.com": false, "spotify.com": false} {
		if got := l.HomeIPOnly(h); got != want {
			t.Errorf("RU %s: %v", h, got)
		}
	}
	cc = "KZ"
	if l.HomeIPOnly("www.youtube.com") {
		t.Error("в Казахстане правило не действует")
	}
}
