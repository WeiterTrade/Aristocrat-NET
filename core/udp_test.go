package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func socksConnect(t *testing.T, proxyPort int, host string, port int) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte{5, 1, 0})
	r := make([]byte, 2)
	io.ReadFull(c, r)
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	c.Write(req)
	resp := make([]byte, 10)
	if _, err := io.ReadFull(c, resp); err != nil || resp[1] != 0 {
		t.Fatalf("SOCKS CONNECT: %v %v", resp, err)
	}
	return c
}

// Протокол, где клиент шлёт большое сообщение, а сервер отвечает только после него
// (загрузка голосового в Telegram/MTProto, потоковое распознавание речи).
// Раньше прокси ждал ответа на первые байты 3 секунды, рвал соединение и повторял —
// такие загрузки не проходили никогда.
func TestUploadNotBrokenByResponseWait(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	const size = 600 * 1024
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				n, _ := io.CopyN(io.Discard, c, size)
				fmt.Fprintf(c, "GOT %d", n)
			}(c)
		}
	}()
	e := newTestEngine(t, freePort(t))
	e.Timeout = 500 * time.Millisecond
	port := ln.Addr().(*net.TCPAddr).Port
	c := socksConnect(t, e.selfPt, "127.0.0.1", port)
	defer c.Close()
	data := make([]byte, size)
	rand.Read(data)
	data[0] = 0xef // не TLS и не HTTP — как обфусцированный MTProto
	go func() {
		// Медленная отправка: пауза дольше e.Timeout посередине.
		c.Write(data[:1000])
		time.Sleep(1200 * time.Millisecond)
		c.Write(data[1000:])
	}()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, _ := io.ReadAll(c)
	if string(got) != fmt.Sprintf("GOT %d", size) {
		t.Fatalf("загрузка оборвана: %q", got)
	}
}

// HTTP POST с телом через обычный HTTP-прокси.
func TestPlainHTTPPostBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "%s %d", r.Method, len(b))
	}))
	defer srv.Close()
	e := newTestEngine(t, freePort(t))
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", e.selfPt))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	body := strings.Repeat("x", 300000)
	fmt.Fprintf(c, "POST %s/up HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s",
		srv.URL, strings.TrimPrefix(srv.URL, "http://"), len(body), body)
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "POST 300000" {
		t.Fatalf("%q", b)
	}
}

func TestCheckable(t *testing.T) {
	ch := []byte{0x16, 3, 1, 0, 10, 1, 0, 0, 6}
	cases := []struct {
		b    []byte
		want bool
	}{
		{ch, true},
		{[]byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"), true},
		{[]byte("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello"), false},
		{[]byte{0xef, 1, 2, 3}, false},
		{nil, false},
	}
	for i, c := range cases {
		if got := checkable(c.b); got != c.want {
			t.Errorf("%d: %v", i, got)
		}
	}
}

// UDP ASSOCIATE: пакет уходит к серверу и ответ возвращается с заголовком SOCKS5.
func TestSOCKS5UDP(t *testing.T) {
	echo, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer echo.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echo.WriteToUDP(append([]byte("ECHO:"), buf[:n]...), a)
		}
	}()
	e := newTestEngine(t, freePort(t))
	e.BlockQUIC = true
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", e.selfPt))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{5, 1, 0})
	io.ReadFull(c, make([]byte, 2))
	c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	resp := make([]byte, 10)
	if _, err := io.ReadFull(c, resp); err != nil || resp[1] != 0 {
		t.Fatalf("UDP ASSOCIATE: %v %v", resp, err)
	}
	relay := &net.UDPAddr{IP: net.IP(resp[4:8]), Port: int(binary.BigEndian.Uint16(resp[8:10]))}
	u, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer u.Close()

	ep := echo.LocalAddr().(*net.UDPAddr)
	pkt := []byte{0, 0, 0, 1, 127, 0, 0, 1}
	pkt = binary.BigEndian.AppendUint16(pkt, uint16(ep.Port))
	pkt = append(pkt, "hello"...)
	u.WriteToUDP(pkt, relay)
	u.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := u.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	host, port, hl, ok := udpHeader(buf[:n])
	if !ok || host != "127.0.0.1" || port != ep.Port || !bytes.Equal(buf[hl:n], []byte("ECHO:hello")) {
		t.Fatalf("ответ: %q %d %q", host, port, buf[:n])
	}

	// QUIC (UDP/443) не пропускается.
	if udpPacketTo443 := udpPacket(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}, []byte("q")); len(udpPacketTo443) == 0 {
		t.Fatal("пустой пакет")
	}
}
