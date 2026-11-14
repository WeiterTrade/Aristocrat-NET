package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	netstack "obhod/internal/wgnetstack"
)

// countingBind — «сервер Cloudflare»: считает мусорные пакеты, проверяет reserved-байты
// и отбрасывает всё, что не похоже на WireGuard (как настоящий сервер).
type countingBind struct {
	conn.Bind
	junk     atomic.Int64
	reserved atomic.Int64
	want     [3]byte
}

func (b *countingBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, p, err := b.Bind.Open(port)
	out := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		fn := fn
		out[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			for {
				n, err := fn(packets, sizes, eps)
				k := 0
				for j := 0; j < n; j++ {
					p := packets[j][:sizes[j]]
					if len(p) < 4 || p[0] < 1 || p[0] > 4 || (p[0] == 1 && len(p) != 148) {
						b.junk.Add(1)
						continue
					}
					if p[1] == b.want[0] && p[2] == b.want[1] && p[3] == b.want[2] {
						b.reserved.Add(1)
					}
					p[1], p[2], p[3] = 0, 0, 0
					packets[k], sizes[k], eps[k] = packets[j], sizes[j], eps[j]
					k++
				}
				if k > 0 || err != nil {
					return k, err
				}
			}
		}
	}
	return out, p, err
}

// Полная проверка туннеля WARP на локальном WireGuard-сервере: перебор узлов (первый
// недоступен), мусор перед рукопожатием, reserved-байты, TCP и DNS внутри туннеля не нужен.
func TestWarpTunnelLocal(t *testing.T) {
	srvPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	cliPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)

	// Сервер: адрес 203.0.113.1, внутри — HTTP-сервер.
	stun, snet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("203.0.113.1")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	sbind := &countingBind{Bind: conn.NewStdNetBind(), want: [3]byte{7, 8, 9}}
	sdev := device.NewDevice(stun, sbind, device.NewLogger(device.LogLevelSilent, ""))
	defer sdev.Close()
	sport := freeUDPPort(t)
	if err := sdev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\npublic_key=%s\nallowed_ip=10.9.0.2/32\n",
		hex.EncodeToString(srvPriv.Bytes()), sport, hex.EncodeToString(cliPriv.PublicKey().Bytes()))); err != nil {
		t.Fatal(err)
	}
	if err := sdev.Up(); err != nil {
		t.Fatal(err)
	}
	hl, err := snet.ListenTCP(&net.TCPAddr{Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(hl, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "INSIDE-WARP") }))

	dir := t.TempDir()
	w := NewWarp(dir, t.Logf)
	acc := &warpAccount{
		PrivateKey: base64.StdEncoding.EncodeToString(cliPriv.Bytes()),
		PeerPublic: base64.StdEncoding.EncodeToString(srvPriv.PublicKey().Bytes()),
		V4:         "10.9.0.2", ClientID: base64.StdEncoding.EncodeToString([]byte{7, 8, 9}),
		Endpoint: fmt.Sprintf("127.0.0.1:%d", sport),
	}
	if err := w.saveAccount(acc); err != nil {
		t.Fatal(err)
	}
	w.Start()
	defer w.Stop()
	if !w.WaitReady(20 * time.Second) {
		st, msg := w.Status()
		t.Fatalf("WARP не подключился: %s %s", st, msg)
	}
	if sbind.junk.Load() < warpJunkCnt {
		t.Fatalf("мусорных пакетов перед рукопожатием: %d", sbind.junk.Load())
	}
	if sbind.reserved.Load() == 0 {
		t.Fatal("reserved-байты не проставлены")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := w.Dial(ctx, "203.0.113.1", 80)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	b, _ := io.ReadAll(c)
	if !strings.Contains(string(b), "INSIDE-WARP") {
		t.Fatalf("%q", b)
	}

	// Через движок: маршрут «всё через WARP».
	e := newTestEngine(t, freePort(t))
	e.Warp = w
	e.Route.Store(RouteWarp)
	sc := socksConnect(t, e.selfPt, "203.0.113.1", 80)
	defer sc.Close()
	fmt.Fprint(sc, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	sc.SetReadDeadline(time.Now().Add(10 * time.Second))
	b, _ = io.ReadAll(sc)
	if !strings.Contains(string(b), "INSIDE-WARP") {
		t.Fatalf("через движок: %q", b)
	}
}

func freeUDPPort(t *testing.T) int {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// Регистрация: разбор ответа API Cloudflare (формат как у настоящего сервера).
func TestWarpRegister(t *testing.T) {
	var gotKey, gotUA string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PATCH" {
			w.WriteHeader(200)
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		gotKey, _ = body["key"].(string)
		gotUA = r.Header.Get("User-Agent")
		fmt.Fprint(w, `{"id":"abc","token":"tok","config":{"client_id":"AQID","peers":[{"public_key":"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=","endpoint":{"v4":"162.159.192.7:0","host":"engage.cloudflareclient.com:2408"}}],"interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110:8a36::1"}}}}`)
	}))
	defer srv.Close()
	w := NewWarp(t.TempDir(), t.Logf)
	w.DialTLS = func(ctx context.Context, host string, port int) (net.Conn, error) {
		if host != "api.cloudflareclient.com" {
			return nil, fmt.Errorf("неожиданный хост %s", host)
		}
		c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "https://"))
		if err != nil {
			return nil, err
		}
		tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true})
		return tc, tc.Handshake()
	}
	a, err := w.account()
	if err != nil {
		t.Fatal(err)
	}
	if a.V4 != "172.16.0.2" || a.ClientID != "AQID" || a.PeerPublic == "" || gotKey == "" || gotUA == "" {
		t.Fatalf("%+v key=%q ua=%q", a, gotKey, gotUA)
	}
	priv, _ := base64.StdEncoding.DecodeString(a.PrivateKey)
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil || base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()) != gotKey {
		t.Fatal("ключи не совпадают")
	}
	// Второй раз — из файла, без запроса.
	srv.Close()
	if b, err := w.account(); err != nil || b.ID != "abc" {
		t.Fatalf("%v %v", b, err)
	}
}
