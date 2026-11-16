package main

// Блокировка рекламы по именам серверов — как в AdGuard DNS и «хостах» AdAway.
//
// Каждое соединение приходит в программу с именем сервера (браузер через прокси, Android —
// через VPN с подменой DNS). Если имя есть в списке рекламных и следящих серверов, соединение
// сразу отклоняется: баннер, всплывающее окно или рекламный ролик просто не загружается.
// Работает для сайтов и приложений (рекламные SDK: AdMob, Unity Ads, AppLovin, Яндекс…).
//
// Списки: встроенный (основные рекламные сети и букмекерская реклама) и фильтр AdGuard DNS,
// который скачивается и обновляется раз в сутки. Реклама внутри самих роликов YouTube идёт
// с тех же серверов, что и видео, — её так не убрать (см. README).

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var errAdBlocked = errors.New("реклама заблокирована")

// Списки, которые скачиваются (первый удачный).
var adListURLs = []string{
	"https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
	"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
}

// Встроенный список: работает сразу, даже без скачивания.
var adBuiltin = []string{
	// Google
	"doubleclick.net", "googlesyndication.com", "googleadservices.com", "googletagservices.com",
	"adservice.google.com", "pagead2.googlesyndication.com", "googleads.g.doubleclick.net",
	"admob.com", "app-measurement.com", "google-analytics.com", "googletagmanager.com",
	// Рекламные SDK в приложениях и играх
	"unityads.unity3d.com", "ads.unity3d.com", "applovin.com", "applvn.com", "ironsrc.com", "ironsrc.mobi",
	"supersonicads.com", "adcolony.com", "vungle.com", "chartboost.com", "inmobi.com", "mopub.com",
	"startappservice.com", "appnext.com", "mintegral.com", "mintegral.net", "rayjump.com", "pangle.io",
	"pangleglobal.com", "an.facebook.com", "fyber.com", "tapjoy.com", "adjust.com", "appsflyer.com",
	"bidmachine.io", "my.target.com",
	// Яндекс, Mail.ru, российские сети
	"an.yandex.ru", "yandexadexchange.net", "adfox.ru", "mc.yandex.ru", "ad.mail.ru", "top-fwz1.mail.ru",
	"adriver.ru", "begun.ru", "directadvert.ru", "buzzoola.com", "otm-r.com", "betweendigital.com",
	"tns-counter.ru", "adhigh.net", "hybrid.ai", "rtb.com.ru", "sape.ru", "relap.io",
	// Сети сайтов, всплывающие окна
	"criteo.com", "criteo.net", "taboola.com", "outbrain.com", "adnxs.com", "rubiconproject.com",
	"pubmatic.com", "openx.net", "smartadserver.com", "amazon-adsystem.com", "adsrvr.org", "moatads.com",
	"scorecardresearch.com", "popads.net", "popcash.net", "propellerads.com", "propellerclick.com",
	"adsterra.com", "exoclick.com", "juicyads.com", "trafficjunky.net", "clickadu.com", "hilltopads.net",
	"a-ads.com", "adskeeper.com", "mgid.com", "marketgid.com", "realsrv.com", "onclickads.net",
	"adcash.com", "richpush.co", "push.house", "admitad.com",
}

// Букмекеры и онлайн-казино — их баннеры на сайтах (части имени).
var adBetting = []string{"1xbet", "1xstavka", "melbet", "mostbet", "vavada", "joycasino", "pin-up.casino", "1win.pro"}

// Никогда не блокируем (вместе с поддоменами) — без них не работают YouTube, Telegram и сама программа.
var adAllow = []string{
	"youtube.com", "googlevideo.com", "ytimg.com", "youtubei.googleapis.com", "youtube.googleapis.com",
	"t.me", "telegram.org", "cloudflareclient.com", "torproject.org", "adguardteam.github.io",
	"raw.githubusercontent.com",
}

type AdBlock struct {
	Enabled func() bool
	Fetch   func(ctx context.Context, url string) ([]byte, error)
	logf    func(string, ...any)
	dir     string

	mu    sync.RWMutex
	set   map[string]struct{}
	allow map[string]struct{}
	n     atomic.Int64 // заблокировано соединений
}

func NewAdBlock(dir string, logf func(string, ...any)) *AdBlock {
	a := &AdBlock{dir: dir, logf: logf}
	set := map[string]struct{}{}
	for _, d := range adBuiltin {
		set[d] = struct{}{}
	}
	a.set = set
	a.allow = map[string]struct{}{}
	for _, d := range adAllow {
		a.allow[d] = struct{}{}
	}
	if b, err := os.ReadFile(a.cachePath()); err == nil {
		a.merge(b)
	}
	return a
}

func (a *AdBlock) cachePath() string { return filepath.Join(a.dir, "adblock.txt") }

// Rules — сколько серверов в списке.
func (a *AdBlock) Rules() int {
	if a == nil {
		return 0
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.set)
}

// Count — сколько рекламных соединений отклонено.
func (a *AdBlock) Count() int64 {
	if a == nil {
		return 0
	}
	return a.n.Load()
}

func (a *AdBlock) On() bool { return a != nil && (a.Enabled == nil || a.Enabled()) }

// Blocked — сервер рекламный: соединение надо отклонить.
func (a *AdBlock) Blocked(host string) bool {
	if !a.On() {
		return false
	}
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if h == "" || net.ParseIP(strings.Trim(h, "[]")) != nil {
		return false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	for s := h; ; {
		if _, ok := a.allow[s]; ok {
			return false
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			break
		}
		s = s[i+1:]
	}
	hit := false
	for s := h; ; {
		if _, ok := a.set[s]; ok {
			hit = true
			break
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			break
		}
		s = s[i+1:]
	}
	if !hit {
		for _, b := range adBetting {
			if strings.Contains(h, b) {
				hit = true
				break
			}
		}
	}
	if hit {
		a.n.Add(1)
	}
	return hit
}

// parseAdList понимает формат AdGuard/AdBlock («||домен^», «@@||домен^» — исключение),
// формат hosts («0.0.0.0 домен») и просто список доменов.
func parseAdList(b []byte) (block, allow []string) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || l[0] == '!' || l[0] == '#' || l[0] == '[' {
			continue
		}
		exc := strings.HasPrefix(l, "@@")
		l = strings.TrimPrefix(l, "@@")
		if strings.HasPrefix(l, "||") {
			l = l[2:]
			if i := strings.IndexByte(l, '$'); i >= 0 {
				if l[i+1:] != "important" {
					continue // правила с условиями (для отдельных клиентов и т. п.) пропускаем
				}
				l = l[:i]
			}
			if !strings.HasSuffix(l, "^") {
				continue
			}
			l = strings.TrimSuffix(l, "^")
		} else if f := strings.Fields(l); len(f) >= 2 && (f[0] == "0.0.0.0" || f[0] == "127.0.0.1" || f[0] == "::") {
			l = f[1]
		} else if exc || strings.ContainsAny(l, " \t") {
			continue
		}
		l = strings.ToLower(strings.TrimSuffix(l, "."))
		if !validAdDomain(l) {
			continue
		}
		if exc {
			allow = append(allow, l)
		} else {
			block = append(block, l)
		}
	}
	return
}

func validAdDomain(d string) bool {
	if len(d) < 4 || len(d) > 253 || !strings.Contains(d, ".") || strings.ContainsAny(d, "*/|^$@:") {
		return false
	}
	switch d {
	case "localhost", "localhost.localdomain", "local", "broadcasthost", "0.0.0.0":
		return false
	}
	return net.ParseIP(d) == nil
}

func (a *AdBlock) merge(b []byte) int {
	block, allow := parseAdList(b)
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, d := range block {
		a.set[d] = struct{}{}
	}
	for _, d := range allow {
		a.allow[d] = struct{}{}
	}
	return len(block)
}

// Update скачивает свежий список раз в сутки (и при первом запуске).
func (a *AdBlock) Update(ctx context.Context) {
	if a == nil || a.Fetch == nil {
		return
	}
	if st, err := os.Stat(a.cachePath()); err == nil && time.Since(st.ModTime()) < 24*time.Hour {
		return
	}
	for _, u := range adListURLs {
		fctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		b, err := a.Fetch(fctx, u)
		cancel()
		if err != nil || len(b) < 1000 {
			if a.logf != nil {
				a.logf("Блокировка рекламы: не удалось скачать список (%s): %v", u, err)
			}
			continue
		}
		block, allow := parseAdList(b)
		if len(block) < 500 {
			continue
		}
		// Сохраняем в простом виде: домен в строке, исключения — с «@@||…^».
		var out bytes.Buffer
		for _, d := range block {
			out.WriteString(d)
			out.WriteByte('\n')
		}
		for _, d := range allow {
			out.WriteString("@@||" + d + "^\n")
		}
		_ = os.MkdirAll(a.dir, 0o700)
		tmp := a.cachePath() + ".tmp"
		if os.WriteFile(tmp, out.Bytes(), 0o600) == nil {
			_ = os.Rename(tmp, a.cachePath())
		}
		a.merge(out.Bytes())
		if a.logf != nil {
			a.logf("Блокировка рекламы: список обновлён — %s серверов", strconv.Itoa(a.Rules()))
		}
		return
	}
}

// Run — обновление списка при запуске и затем раз в сутки.
func (a *AdBlock) Run() {
	for {
		a.Update(context.Background())
		time.Sleep(6 * time.Hour)
	}
}

// httpFetch — загрузка через обход DPI (dialTLS) — списки на GitHub могут быть недоступны напрямую.
func httpFetch(dialTLS func(ctx context.Context, host string, port int) (net.Conn, error)) func(ctx context.Context, url string) ([]byte, error) {
	cl := &http.Client{Transport: &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			h, p, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port, _ := strconv.Atoi(p)
			return dialTLS(ctx, h, port)
		},
		ForceAttemptHTTP2: false,
	}}
	return func(ctx context.Context, url string) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := cl.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, errors.New(resp.Status)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	}
}
