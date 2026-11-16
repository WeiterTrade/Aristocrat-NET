package main

// Передача своих мостов между устройствами в одной сети Wi-Fi (тот же протокол, что
// в Android-версии, BridgeShare.java): можно отправить мосты с телефона на ПК, с ПК на
// телевизор и т. д. Поиск — широковещательный UDP, передача — TCP. Принятые мосты
// применяются только после подтверждения пользователем.

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	shareUDPPort = 47811
	shareTCPPort = 47812
	shareProbe   = "ARISTONET?1|"
	shareHere    = "ARISTONET!1|"
	shareHeader  = "ARISTONET-BRIDGES 1"
)

type ShareDevice struct {
	IP   string `json:"ip"`
	Name string `json:"name"`
}

type ShareOffer struct {
	ID    string `json:"id"`
	From  string `json:"from"`
	Count int    `json:"count"`
	text  string
}

type Share struct {
	Name  string
	logf  func(string, ...any)
	nonce string

	mu      sync.Mutex
	offer   *ShareOffer
	onOffer func() // пришли мосты (нативное окно показывает вопрос)
}

func NewShare(logf func(string, ...any)) *Share {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	name, _ := os.Hostname()
	if name == "" {
		name = "Компьютер"
	}
	return &Share{Name: name, logf: logf, nonce: hex.EncodeToString(b)}
}

// Listen — отвечать на поиск и принимать мосты (работает, пока работает программа).
func (s *Share) Listen() {
	go func() {
		pc, err := net.ListenPacket("udp4", ":"+itoa(shareUDPPort))
		if err != nil {
			s.logf("Передача мостов: порт %d занят — это устройство не будет видно другим", shareUDPPort)
			return
		}
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			m := string(buf[:n])
			if !strings.HasPrefix(m, shareProbe) || strings.TrimPrefix(m, shareProbe) == s.nonce {
				continue
			}
			_, _ = pc.WriteTo([]byte(shareHere+s.Name), from)
		}
	}()
	go func() {
		ln, err := net.Listen("tcp4", ":"+itoa(shareTCPPort))
		if err != nil {
			return
		}
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.receive(c)
		}
	}()
}

func (s *Share) receive(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	b, _ := io.ReadAll(io.LimitReader(c, 64*1024))
	msg := string(b)
	head, rest, ok := strings.Cut(msg, "\n")
	if !ok || strings.TrimSpace(head) != shareHeader {
		return
	}
	from, text, _ := strings.Cut(rest, "\n")
	text = strings.TrimSpace(strings.ReplaceAll(text, "\r\n", "\n"))
	n := len(splitBridgeLines(text))
	if n == 0 {
		return
	}
	_, _ = c.Write([]byte("OK\n"))
	id := make([]byte, 6)
	_, _ = rand.Read(id)
	s.mu.Lock()
	s.offer = &ShareOffer{ID: hex.EncodeToString(id), From: strings.TrimSpace(from), Count: n, text: text}
	cb := s.onOffer
	s.mu.Unlock()
	s.logf("Получены мосты (%d) с устройства «%s» — ждут подтверждения", n, strings.TrimSpace(from))
	if cb != nil {
		cb()
	}
}

// Offer — мосты, ждущие подтверждения (nil — нет).
func (s *Share) Offer() *ShareOffer {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.offer == nil {
		return nil
	}
	o := *s.offer
	return &o
}

// Take — забрать мосты по id (после ответа пользователя предложение исчезает).
func (s *Share) Take(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.offer == nil || (id != "" && s.offer.ID != id) {
		return "", false
	}
	t := s.offer.text
	s.offer = nil
	return t, true
}

// Discover ищет другие устройства с Aristocrat NET в локальной сети.
func (s *Share) Discover(wait time.Duration) []ShareDevice {
	pc, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil
	}
	defer pc.Close()
	targets := []net.IP{net.IPv4bcast}
	mine := map[string]bool{}
	if ifs, err := net.Interfaces(); err == nil {
		for _, ifc := range ifs {
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := ifc.Addrs()
			for _, a := range addrs {
				ipn, ok := a.(*net.IPNet)
				if !ok || ipn.IP.To4() == nil {
					continue
				}
				ip4 := ipn.IP.To4()
				mine[ip4.String()] = true
				mask := ipn.Mask
				if len(mask) == 16 {
					mask = mask[12:]
				}
				if len(mask) != 4 {
					continue
				}
				bc := make(net.IP, 4)
				for i := range bc {
					bc[i] = ip4[i] | ^mask[i]
				}
				targets = append(targets, bc)
			}
		}
	}
	probe := []byte(shareProbe + s.nonce)
	found := map[string]string{}
	end := time.Now().Add(wait)
	next := time.Time{}
	buf := make([]byte, 512)
	for time.Now().Before(end) {
		if time.Now().After(next) {
			for _, t := range targets {
				_, _ = pc.WriteTo(probe, &net.UDPAddr{IP: t, Port: shareUDPPort})
			}
			next = time.Now().Add(800 * time.Millisecond)
		}
		_ = pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		ua, ok := from.(*net.UDPAddr)
		m := string(buf[:n])
		if ok && strings.HasPrefix(m, shareHere) && !mine[ua.IP.String()] {
			found[ua.IP.String()] = strings.TrimPrefix(m, shareHere)
		}
	}
	out := make([]ShareDevice, 0, len(found))
	for ip, name := range found {
		out = append(out, ShareDevice{IP: ip, Name: name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Send отправляет мосты на устройство ip.
func (s *Share) Send(ip, text string) error {
	if net.ParseIP(ip) == nil {
		return errBadIP
	}
	c, err := net.DialTimeout("tcp4", net.JoinHostPort(ip, itoa(shareTCPPort)), 4*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := io.WriteString(c, shareHeader+"\n"+s.Name+"\n"+strings.TrimSpace(text)+"\n"); err != nil {
		return err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	l, _ := bufio.NewReader(c).ReadString('\n')
	if !strings.HasPrefix(l, "OK") {
		return errShareRefused
	}
	return nil
}

type shareErr string

func (e shareErr) Error() string { return string(e) }

const (
	errBadIP        = shareErr("неверный адрес устройства")
	errShareRefused = shareErr("устройство не приняло мосты")
)

// splitBridgeLines — строки-мосты без пустых, комментариев и слова «Bridge».
func splitBridgeLines(text string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "Bridge "))
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
