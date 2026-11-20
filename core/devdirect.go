package main

// Прямое подключение к серверу разработчика с белым IP (маршрут «Ебаная Чукотка»).
// Соединение — TLS (для провайдера это обычный HTTPS), сертификат сервера закреплён
// в коде подключения, поэтому подменить сервер нельзя. Внутри — тот же прокси раздачи
// с входом по логину: ключ доступа + номер установки, сведения о пользователе — в пароле.
//
// Код подключения (секрет GitHub DEV_DIRECT): d1:<IP>:<порт>:<sha256 сертификата>:<ключ доступа>.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

// devDirectCode — код прямого подключения (задаётся при сборке).
var devDirectCode = ""

const RouteMoscow = "moscow" // всё через сервер разработчика с белым IP

type directCode struct {
	host  string
	port  int
	fp    string // sha256 сертификата (hex)
	token string // ключ доступа (32 hex)
}

func parseDirectCode(code string) (directCode, bool) {
	f := strings.Split(strings.TrimSpace(code), ":")
	if len(f) != 5 || f[0] != "d1" {
		return directCode{}, false
	}
	port, err := strconv.Atoi(f[2])
	ip := net.ParseIP(f[1])
	if err != nil || port < 1 || port > 65535 || ip == nil || ip.To4() == nil || len(f[3]) != 64 || len(f[4]) != 32 {
		return directCode{}, false
	}
	if _, err := hex.DecodeString(f[3]); err != nil {
		return directCode{}, false
	}
	if _, err := hex.DecodeString(f[4]); err != nil {
		return directCode{}, false
	}
	return directCode{host: f[1], port: port, fp: strings.ToLower(f[3]), token: strings.ToLower(f[4])}, true
}

// directAvailable — в сборке есть маршрут «Ебаная Чукотка»: только Edward Version и сборки
// разработчика (в сборке для всех пользователей его нет, даже если код случайно вшит).
func directAvailable() bool {
	_, ok := parseDirectCode(devDirectCode)
	return ok && (edition == "edward" || devBuild)
}

func init() {
	if directAvailable() {
		RouteNames[RouteMoscow] = "Ебаная Чукотка"
	}
}

// NewDirectLink — путь через сервер с белым IP (nil — в сборке нет кода).
func NewDirectLink(dir string, logf func(string, ...any)) *DevLink {
	dc, ok := parseDirectCode(devDirectCode)
	if !ok || !directAvailable() {
		return nil
	}
	cfg := &tls.Config{
		ServerName:         "www.microsoft.com", // для провайдера — обычный HTTPS к известному сайту
		InsecureSkipVerify: true,                // проверка — по закреплённому отпечатку ниже
		NextProtos:         []string{"h2", "http/1.1"},
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("сервер не прислал сертификат")
			}
			sum := sha256.Sum256(raw[0])
			if hex.EncodeToString(sum[:]) != dc.fp {
				return errors.New("чужой сертификат сервера (код подключения устарел или соединение подменено)")
			}
			return nil
		},
	}
	addr := net.JoinHostPort(dc.host, strconv.Itoa(dc.port))
	d := &DevLink{logf: logf, label: "сервер разработчика (" + dc.host + ")", prefix: dc.token, id: installID(dir)}
	d.dialTo = func(ctx context.Context) (net.Conn, error) {
		dl := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
		raw, err := dl.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		tc := tls.Client(raw, cfg)
		hctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		if err := tc.HandshakeContext(hctx); err != nil {
			raw.Close()
			return nil, err
		}
		return tc, nil
	}
	return d
}
