package main

// Местные сайты — напрямую, с настоящим IP.
//
// Российские и казахстанские сайты и сервисы (банки, госуслуги, маркетплейсы, Яндекс, VK…)
// не заблокированы, зато часто не пускают с чужих IP. Поэтому они всегда идут напрямую —
// даже в режимах «Всё через Tor» и «Всё через WARP»:
//   • по имени: зоны .ru .рф .su .kz .қаз и известные домены этих сервисов в других зонах;
//   • по адресу: если сервер находится в России или Казахстане (база GeoIP из Tor).
//
// Обратный случай — сервисы, которые сами закрылись для России (Spotify): у пользователя
// в России они идут через Tor (IP другой страны) даже в режиме «Авто».

import (
	"bufio"
	"context"
	"encoding/binary"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Зоны и домены, которые всегда открываются напрямую.
var localSuffixes = []string{
	// Россия и Казахстан
	"ru", "su", "xn--p1ai" /* .рф */, "xn--d1acj3b" /* .дети */, "moscow", "xn--80adxhks", /* .москва */
	"kz", "xn--80ao21a", /* .қаз */
	// Яндекс
	"yandex.net", "yandex.com", "yandex.kz", "yandex.by", "yastatic.net", "yandex.cloud", "yandexcloud.net",
	"yandexadexchange.net", "yandex-team.com", "kinopoisk.ru",
	// VK, Одноклассники, Mail.ru
	"vk.com", "vk.me", "vk.link", "vkuser.net", "userapi.com", "vk-cdn.net", "vkuseraudio.net", "vkuservideo.net",
	"mycdn.me", "okcdn.ru", "mradx.net", "vk.company",
	// Маркетплейсы, сервисы, банки
	"2gis.com", "2gis.kz", "dgis.ru", "ozone.ru", "wbbasket.ru", "wbstatic.net", "avito.st",
	"sberbank.com", "sber.com", "tinkoff.com", "tbank-online.com", "tbank.ru", "kaspi.kz", "halykbank.com",
	"rustore.ru", "max.ru", "oneme.ru",
}

// Сервисы, которые сами не работают в России: у пользователя в России — через Tor.
var geoBlockedRU = []string{
	"spotify.com", "spotify.net", "scdn.co", "pscdn.co", "spotifycdn.com", "spotifycdn.net", "spotilocal.com",
	"spotify.map.fastly.net", "byspotify.com",
}

func matchSuffix(host string, list []string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, s := range list {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// isGeoBlockedRU — сервис, закрытый для России (в том числе его CDN: …spotify…akamaized.net).
func isGeoBlockedRU(host string) bool {
	h := strings.ToLower(host)
	return matchSuffix(h, geoBlockedRU) || (strings.Contains(h, "spotify") &&
		(strings.HasSuffix(h, ".akamaized.net") || strings.HasSuffix(h, ".fastly.net") || strings.HasSuffix(h, ".edgekey.net")))
}

// ---------------------------------------------------------------------------
// GeoIP: файл geoip из Tor (строки «начало,конец,страна», адреса IPv4 числами).

type geoRange struct {
	lo, hi uint32
	cc     [2]byte
}

type GeoIP struct {
	mu     sync.RWMutex
	ranges []geoRange
}

// Load читает файл (повторный вызов с тем же файлом ничего не меняет).
func (g *GeoIP) Load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var rs []geoRange
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := sc.Text()
		if l == "" || l[0] == '#' {
			continue
		}
		p := strings.Split(l, ",")
		if len(p) != 3 || len(p[2]) != 2 {
			continue
		}
		lo, err1 := strconv.ParseUint(p[0], 10, 32)
		hi, err2 := strconv.ParseUint(p[1], 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		rs = append(rs, geoRange{uint32(lo), uint32(hi), [2]byte{p[2][0] &^ 0x20, p[2][1] &^ 0x20}})
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].lo < rs[j].lo })
	g.mu.Lock()
	g.ranges = rs
	g.mu.Unlock()
	return sc.Err()
}

func (g *GeoIP) Loaded() bool {
	if g == nil {
		return false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.ranges) > 0
}

// Country — код страны адреса IPv4 ("" — неизвестно).
func (g *GeoIP) Country(ip net.IP) string {
	if g == nil {
		return ""
	}
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	n := binary.BigEndian.Uint32(v4)
	g.mu.RLock()
	defer g.mu.RUnlock()
	i := sort.Search(len(g.ranges), func(i int) bool { return g.ranges[i].lo > n }) - 1
	if i >= 0 && n <= g.ranges[i].hi {
		return string(g.ranges[i].cc[:])
	}
	return ""
}

// ---------------------------------------------------------------------------

// Local — правила «напрямую» и «через Tor по стране» для движка.
type Local struct {
	Geo         *GeoIP
	Enabled     func() bool   // «местные сайты напрямую» включено
	UserCountry func() string // страна пользователя (по настоящему IP), например "RU"
	Resolve     func(ctx context.Context, host string) ([]net.IP, error)

	mu    sync.Mutex
	cache map[string]localVerdict // решение по адресу сервера (чтобы не спрашивать DNS каждый раз)
}

type localVerdict struct {
	direct bool
	exp    time.Time
}

var localCountries = map[string]bool{"RU": true, "KZ": true}

// Direct — сайт российский или казахстанский: идти напрямую с настоящим IP.
func (l *Local) Direct(host string) bool {
	if l == nil || (l.Enabled != nil && !l.Enabled()) || isLocalAddr(host) {
		return false
	}
	if matchSuffix(host, localSuffixes) {
		return true
	}
	if !l.Geo.Loaded() {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return localCountries[l.Geo.Country(ip)]
	}
	if l.Resolve == nil {
		return false
	}
	key := strings.ToLower(host)
	l.mu.Lock()
	v, ok := l.cache[key]
	l.mu.Unlock()
	if ok && time.Now().Before(v.exp) {
		return v.direct
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := l.Resolve(ctx, host)
	direct := err == nil && len(ips) > 0 && localCountries[l.Geo.Country(ips[0])]
	ttl := 10 * time.Minute
	if err != nil {
		ttl = time.Minute
	}
	l.mu.Lock()
	if l.cache == nil || len(l.cache) > 20000 {
		l.cache = map[string]localVerdict{}
	}
	l.cache[key] = localVerdict{direct, time.Now().Add(ttl)}
	l.mu.Unlock()
	return direct
}

// DirectIP — то же для адреса (UDP).
func (l *Local) DirectIP(ip net.IP) bool {
	if l == nil || (l.Enabled != nil && !l.Enabled()) || !l.Geo.Loaded() {
		return false
	}
	return localCountries[l.Geo.Country(ip)]
}

// YouTube и его серверы видео и картинок.
var youtubeDomains = []string{
	"youtube.com", "youtu.be", "yt.be", "googlevideo.com", "ytimg.com", "ggpht.com", "youtube-nocookie.com",
	"youtubei.googleapis.com", "youtube.googleapis.com", "youtubekids.com", "youtube-ui.l.google.com",
}

func isYouTube(host string) bool { return matchSuffix(host, youtubeDomains) }

// HomeIPOnly — сайт должен видеть российский IP пользователя: YouTube в России.
// Google не продаёт рекламу в России, поэтому с российским IP YouTube идёт без рекламы.
// Через Tor или чужую страну реклама вернулась бы, поэтому YouTube у пользователя
// в России всегда идёт напрямую (с обходом замедления) или через WARP (он даёт IP той же страны).
func (l *Local) HomeIPOnly(host string) bool {
	if l == nil || (l.Enabled != nil && !l.Enabled()) || l.UserCountry == nil || l.UserCountry() != "RU" {
		return false
	}
	return isYouTube(host)
}

// NeedsForeignIP — сервис закрыт для страны пользователя (Spotify в России).
func (l *Local) NeedsForeignIP(host string) bool {
	if l == nil || l.UserCountry == nil || l.UserCountry() != "RU" {
		return false
	}
	return isGeoBlockedRU(host)
}
