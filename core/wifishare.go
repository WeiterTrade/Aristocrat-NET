package main

// Раздача интернета по Wi-Fi без «раздачи» оператора (Android): телефон создаёт сеть Wi-Fi Direct,
// а устройства в ней выходят в интернет через этот прокси. Все соединения открывает сам телефон,
// поэтому для оператора это обычный трафик телефона (тот же TTL, тот же «отпечаток» системы).
// Прокси принимает подключения только из домашних сетей (192.168.x.x, 10.x.x.x, 172.16–31.x.x).

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// ServeLAN — дополнительный вход в прокси для устройств домашней сети.
func (e *Engine) ServeLAN(ln net.Listener) {
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if !lanPeer(c.RemoteAddr()) {
				c.Close()
				continue
			}
			go e.handle(c)
		}
	}()
}

// lanPeer — адрес из домашней сети (не из интернета).
func lanPeer(a net.Addr) bool {
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return false
	}
	ip := ta.IP
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// servePage — ответ на запрос к самому прокси: http://<адрес телефона>:<порт>/
// /proxy.pac — файл автонастройки прокси (в настройках Wi-Fi: «Прокси → Автоматически»).
func servePage(c net.Conn, req *http.Request) {
	host := req.Host
	if host == "" {
		host = c.LocalAddr().String()
	}
	var ctype, body string
	if strings.HasSuffix(req.URL.Path, ".pac") || strings.HasSuffix(req.URL.Path, "wpad.dat") {
		ctype = "application/x-ns-proxy-autoconfig"
		body = fmt.Sprintf("function FindProxyForURL(url, host) {\n"+
			"  if (isPlainHostName(host) || shExpMatch(host, \"192.168.*\") || shExpMatch(host, \"10.*\")) return \"DIRECT\";\n"+
			"  return \"PROXY %s; SOCKS5 %s\";\n}\n", host, host)
	} else {
		ctype = "text/html; charset=utf-8"
		body = "<!DOCTYPE html><meta charset=utf-8><meta name=viewport content='width=device-width'>" +
			"<title>Aristocrat NET</title><body style='font:18px sans-serif;margin:2em'>" +
			"<h2>Aristocrat NET: раздача работает</h2>" +
			"<p>Прокси: <b>" + htmlEsc(host) + "</b></p>" +
			"<p>Автонастройка прокси: <b>http://" + htmlEsc(host) + "/proxy.pac</b></p></body>"
	}
	fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", ctype, len(body))
	_, _ = io.WriteString(c, body)
}

func htmlEsc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "'", "&#39;", "\"", "&quot;").Replace(s)
}
