// Обход — локальный обход блокировок без VPN-подписок и своих серверов.
//
//   - Сначала соединение идёт напрямую с обходом DPI (дробление ClientHello, disorder), DNS — через DoH.
//   - Если сайт заблокирован по IP или обход DPI не помог — автоматически через Tor (с мостами).
//
// На ПК программа работает как системный прокси с веб-интерфейсом,
// на Android — как ядро за системным VPN (запускается приложением с флагом -headless).
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const appName = "Obhod" // имя папки данных (не меняется — чтобы сохранить настройки)

// appTitle — название программы для пользователя.
const appTitle = "Aristocrat NET"

var appVersion = "0.10.0" // перезаписывается при сборке: -ldflags "-X main.appVersion=..."

const torSocksAddr = "127.0.0.1:9077"

//go:embed ui/index.html
var indexHTML []byte

//go:embed ui/planet-on.png
var planetOnPNG []byte

//go:embed ui/planet-off.png
var planetOffPNG []byte

//go:embed ui/logo.png
var logoWebPNG []byte

//go:embed ui/brand.png
var brandPNG []byte

type Settings struct {
	Port          int               `json:"port"`
	Mode          string            `json:"mode"`  // метод обхода DPI: auto | метод
	Route         string            `json:"route"` // auto | dpi | warp | tor
	Heavy         string            `json:"heavy"` // запасной путь в режиме «Авто»: warp-tor | warp | tor
	Bridges       string            `json:"bridges"`
	CustomBridges string            `json:"custom_bridges"`
	TorCountry    string            `json:"tor_country"` // страна выхода из Tor; пусто — любая
	SysProxy      bool              `json:"sys_proxy"`
	DoH           string            `json:"doh"`
	AutoStart     bool              `json:"auto_start"`
	KeepLocal     bool              `json:"keep_local"`          // российские и казахстанские сайты — напрямую, с настоящим IP
	GeoTor        bool              `json:"geo_tor"`             // в России: Spotify и др. закрытые для России сервисы — через Tor
	AdBlock       bool              `json:"adblock"`             // блокировать рекламу и слежку
	BridgesAsked  bool              `json:"bridges_asked"`       // при первом запуске уже предлагали получить мосты
	CloseAction   string            `json:"close_action"`        // крестик окна: "" — спрашивать, tray — в трей, quit — выход
	DevMode       bool              `json:"dev_mode,omitempty"`  // сборка разработчика: режим разработчика включён (по паролю)
	DevShare      bool              `json:"dev_share,omitempty"` // сборка разработчика: раздача включена
	Learned       map[string]string `json:"learned"`
	Ver           int               `json:"ver"`
}

const settingsVer = 5

func defaultSettings() Settings {
	return Settings{Port: 8881, Mode: "auto", Route: RouteAuto, Heavy: HeavyWarpTor, Bridges: "auto",
		SysProxy: true, DoH: "cloudflare", AutoStart: true, KeepLocal: true, GeoTor: true, AdBlock: true}
}

func (s *Settings) normalize() {
	d := defaultSettings()
	if s.Port < 1024 || s.Port > 65535 {
		s.Port = d.Port
	}
	if HeavyNames[s.Heavy] == "" {
		s.Heavy = d.Heavy
	}
	if s.Mode != "auto" && (!validStrategy(s.Mode) || isUpstreamStrat(s.Mode)) {
		s.Mode = d.Mode
	}
	if RouteNames[s.Route] == "" {
		s.Route = d.Route
	}
	if BridgeNames[s.Bridges] == "" {
		s.Bridges = d.Bridges
	}
	if TorCountries[s.TorCountry] == "" {
		s.TorCountry = ""
	}
	if s.CloseAction != "tray" && s.CloseAction != "quit" {
		s.CloseAction = ""
	}
	if DoHServers[s.DoH] == "" {
		s.DoH = d.DoH
	}
}

type App struct {
	mu       sync.Mutex
	dir      string
	s        Settings
	eng      *Engine
	res      *Resolver
	tor      *Tor
	torMu    sync.Mutex // запуски Tor — строго по одному
	torRC    string     // torrc запущенного сейчас tor (чтобы не перезапускать без нужды)
	torPhase int        // этап автовыбора мостов (см. TorOptions.AutoPhase)
	warp     *Warp
	torSocks string // внешний Tor (Android)
	country  string // страна пользователя по настоящему IP ("RU", "KZ"…)
	geo      *GeoIP
	token    string
	addr     string
	logs     []string
	proxyErr string
	torErr   string
	ads      *AdBlock
	dev      *DevServer // раздача через Tor (только сборка разработчика)
	share    *Share     // передача мостов в локальной сети (на ПК; на Android — в приложении)
	hideUI   func()     // Linux: закрыть окно WebKitGTK (программа остаётся в трее)
	showUI   func()     // показать окно программы (нативное окно на Windows, браузер на Linux)
}

func (a *App) logf(f string, args ...any) {
	line := time.Now().Format("15:04:05 ") + fmt.Sprintf(f, args...)
	a.mu.Lock()
	a.logs = append(a.logs, line)
	if len(a.logs) > 400 {
		a.logs = a.logs[len(a.logs)-400:]
	}
	a.mu.Unlock()
}

func (a *App) load() {
	a.s = defaultSettings()
	if b, err := os.ReadFile(filepath.Join(a.dir, "settings.json")); err == nil {
		_ = json.Unmarshal(b, &a.s)
	}
	// v2: прежний вариант по умолчанию «Snowflake» часто не подключается — переводим на «Автовыбор».
	if a.s.Ver < 2 && a.s.Bridges == "snowflake" {
		a.s.Bridges = "auto"
	}
	// v3: появился WARP — по умолчанию сначала WARP, затем Tor.
	// v4: местные сайты напрямую и Spotify через Tor — включены по умолчанию.
	if a.s.Ver < 4 {
		a.s.KeepLocal, a.s.GeoTor = true, true
	}
	if a.s.Ver < 3 {
		a.s.Heavy = HeavyWarpTor
	}
	// v5: блокировка рекламы — включена по умолчанию.
	if a.s.Ver < 5 {
		a.s.AdBlock = true
	}
	a.s.Ver = settingsVer
	a.s.normalize()
}

func (a *App) save() {
	a.mu.Lock()
	a.s.Learned = a.eng.Learned()
	b, _ := json.MarshalIndent(a.s, "", "  ")
	a.mu.Unlock()
	_ = os.MkdirAll(a.dir, 0o700)
	tmp := filepath.Join(a.dir, "settings.json.tmp")
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, filepath.Join(a.dir, "settings.json"))
	}
}

// startTor запускает встроенный tor (на ПК). Вызовы идут строго по одному; если tor уже
// работает с теми же настройками, он не перезапускается.
func (a *App) startTor() {
	a.torMu.Lock()
	defer a.torMu.Unlock()
	a.mu.Lock()
	bridges, custom, country := a.s.Bridges, a.s.CustomBridges, a.s.TorCountry
	a.mu.Unlock()
	// Tor уже работает с теми же настройками — не трогаем.
	key := fmt.Sprintf("%s|%s|%s|%d", bridges, custom, country, a.torPhase)
	if a.tor.Enabled() && key == a.torRC {
		return
	}
	a.torErr = ""
	paths, err := FindTor()
	if err != nil {
		a.torErr = err.Error()
		a.logf("Tor: %v", err)
		return
	}
	// Tor запускается из папки данных программы, и все пути в torrc — относительные и только латиницей:
	// tor на Windows читает пути в однобайтовой кодировке (ломаются «C:\Users\Олег\…»),
	// а путь к транспорту в ClientTransportPlugin не может содержать пробелы («Program Files»).
	_ = os.MkdirAll(filepath.Join(a.dir, "tor-data"), 0o700)
	ptDir := filepath.Dir(paths.PTConfig)
	if paths.PTConfig != "" {
		if err := syncDir(ptDir, filepath.Join(a.dir, "pt")); err != nil {
			a.torErr = "не удалось подготовить транспорты Tor: " + err.Error()
			a.logf("Tor: %s", a.torErr)
			return
		}
		ptDir = "pt"
	}
	geoDir := paths.GeoIPDir
	if geoDir != "" {
		if err := syncDir(geoDir, filepath.Join(a.dir, "geoip")); err == nil {
			geoDir = "geoip"
		}
	}
	// Свободный порт для SOCKS Tor: фиксированный мог остаться занят старой копией tor.
	socks := torSocksAddr
	if l, err := net.Listen("tcp", "127.0.0.1:0"); err == nil {
		socks = l.Addr().String()
		l.Close()
	}
	// Свои мосты: недоступные убираем, быстрые — первыми (Tor подключается и работает быстрее).
	if bridges == "custom" || bridges == "auto" {
		custom = rankBridges(custom, func(ctx context.Context, addr string) (net.Conn, error) {
			h, p, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port, _ := strconv.Atoi(p)
			return a.eng.dial(ctx, h, port)
		}, a.logf)
	}
	torrc, err := BuildTorrc(TorOptions{
		Bridges: bridges, Custom: custom, SocksAddr: socks, DataDir: "tor-data",
		PTConfigPath: paths.PTConfig, PTDir: ptDir, WorkDir: a.dir, GeoIPDir: geoDir, ExitCountry: country,
		AutoPhase: a.torPhase, ClientAuthDir: relIfSet(writeDevClientAuth(filepath.Join(a.dir, "tor-auth")), "tor-auth"),
	})
	if err != nil {
		a.torErr = err.Error()
		a.logf("Tor: %v", err)
		return
	}
	a.torRC = key
	torrcPath := filepath.Join(a.dir, "torrc")
	if err := os.WriteFile(torrcPath, []byte(torrc), 0o600); err != nil {
		a.torErr = err.Error()
		return
	}
	if err := a.tor.Start(paths.Exe, "torrc", paths.LibDir, a.dir, socks, filepath.Join(a.dir, "tor.pid")); err != nil {
		a.torErr = err.Error()
		a.logf("Tor: %v", err)
	}
}

// settings возвращает копию текущих настроек.
func (a *App) settings() Settings {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.s
}

// applySettings применяет и сохраняет настройки (используют веб-интерфейс и нативное окно).
func (a *App) applySettings(s Settings) error {
	s.normalize()
	a.mu.Lock()
	old := a.s
	a.s.Port, a.s.Mode, a.s.Route, a.s.SysProxy, a.s.DoH, a.s.AutoStart = s.Port, s.Mode, s.Route, s.SysProxy, s.DoH, s.AutoStart
	a.s.KeepLocal, a.s.GeoTor, a.s.AdBlock, a.s.CloseAction = s.KeepLocal, s.GeoTor, s.AdBlock, s.CloseAction
	a.s.Bridges, a.s.CustomBridges, a.s.Heavy, a.s.TorCountry = s.Bridges, s.CustomBridges, s.Heavy, s.TorCountry
	a.mu.Unlock()
	a.eng.Mode.Store(s.Mode)
	a.eng.Route.Store(s.Route)
	a.res.SetPreferred(s.DoH)
	a.save()
	if a.eng.Running() {
		if s.Port != old.Port || s.SysProxy != old.SysProxy {
			a.disable()
			return a.enable()
		}
		torChanged := s.Bridges != old.Bridges || s.CustomBridges != old.CustomBridges || s.TorCountry != old.TorCountry
		if torChanged {
			a.torMu.Lock()
			a.torPhase = 0
			a.torMu.Unlock()
		}
		a.startUpstreams(torChanged)
	}
	return nil
}

// Запасные пути в режиме «Авто».
const (
	HeavyWarpTor = "warp-tor"
	HeavyWarp    = "warp"
	HeavyTor     = "tor"
)

var HeavyNames = map[string]string{
	HeavyWarpTor: "Сначала WARP, затем Tor",
	HeavyWarp:    "Только WARP",
	HeavyTor:     "Только Tor",
}

var heavyOrder = []string{HeavyWarpTor, HeavyWarp, HeavyTor}

// needs — какие запасные пути нужны при текущих настройках.
func (s Settings) needs() (warp, tor bool) {
	switch s.Route {
	case RouteDev:
		return s.Heavy != HeavyTor, true // к разработчику — через Tor; запасной путь — как в «Авто»
	case RouteWarp:
		return true, false
	case RouteTor:
		return false, true
	case RouteDPI:
		return false, false
	}
	return s.Heavy != HeavyTor, s.Heavy != HeavyWarp
}

// watchTorBridges — автовыбор мостов: если Tor долго не продвигается на snowflake,
// перезапускаем его с obfs4 и meek, и наоборот (провайдеры блокируют разные мосты по-разному).
func (a *App) watchTorBridges() {
	for range time.Tick(10 * time.Second) {
		if !a.eng.Running() || !a.tor.Stalled() {
			continue
		}
		a.mu.Lock()
		auto := a.s.Bridges == "auto"
		a.mu.Unlock()
		if !auto {
			continue
		}
		a.torMu.Lock()
		a.torPhase = 1 - a.torPhase
		phase := a.torPhase
		a.torMu.Unlock()
		if phase == 1 {
			a.logf("Tor: через snowflake не подключается — пробую мосты obfs4 и meek")
		} else {
			a.logf("Tor: запасные мосты тоже не подключаются — снова пробую snowflake")
		}
		if a.torSocks != "" {
			// Android: Tor запускает приложение — оно увидит сообщение выше в журнале и само
			// перезапустит TorService с другими мостами. Здесь только сбрасываем ожидание.
			a.tor.UseExternal(a.torSocks)
			continue
		}
		a.startTor()
	}
}

// needs — нужны ли WARP и Tor: по настройкам, а в России Tor нужен ещё и для Spotify
// (если только пользователь не выбрал «Только обход DPI»).
func (a *App) needs() (warp, tor bool) {
	a.mu.Lock()
	st, cc := a.s, a.country
	a.mu.Unlock()
	warp, tor = st.needs()
	if st.GeoTor && cc == "RU" && st.Route != RouteDPI {
		tor = true
	}
	return warp, tor
}

// detectCountry узнаёт страну пользователя по настоящему IP (нужно для правила «Spotify — через Tor в России»).
func (a *App) detectCountry() {
	for delay := 5 * time.Second; ; delay *= 2 {
		_, cc, err := publicIP()
		if err == nil && cc != "" {
			cc = strings.ToUpper(cc)
			a.mu.Lock()
			changed := a.country != cc
			a.country = cc
			a.mu.Unlock()
			if changed {
				a.logf("Страна по настоящему IP: %s", cc)
				if a.eng.Running() {
					a.startUpstreams(false)
				}
			}
			delay = 30 * time.Minute / 2 // потом перепроверяем раз в полчаса (сеть могла смениться)
		}
		if delay > 30*time.Minute {
			delay = 30 * time.Minute
		}
		time.Sleep(delay)
	}
}

// userCountry — страна пользователя по настоящему IP ("" — ещё не известна).
func (a *App) userCountry() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.country
}

// loadGeoIP загружает базу стран (файл geoip из Tor) для правила «местные сайты напрямую».
func (a *App) loadGeoIP(dir string) {
	var cands []string
	if dir != "" {
		cands = append(cands, filepath.Join(dir, "geoip"))
	}
	cands = append(cands, filepath.Join(a.dir, "geoip", "geoip"))
	if p, err := FindTor(); err == nil && p.GeoIPDir != "" {
		cands = append(cands, filepath.Join(p.GeoIPDir, "geoip"))
	}
	for _, c := range cands {
		if err := a.geo.Load(c); err == nil && a.geo.Loaded() {
			return
		}
	}
	a.logf("База стран (GeoIP) не найдена — местные сайты определяются только по домену")
}

// startUpstreams запускает или останавливает WARP и Tor под текущие настройки.
// restartTor — перезапустить Tor (сменились мосты).
func (a *App) startUpstreams(restartTor bool) {
	if a.settings().Route == RouteDev && a.eng.Dev != nil {
		a.eng.Dev.Watch(func() bool { return a.eng.Running() && a.settings().Route == RouteDev })
	}
	needWarp, needTor := a.needs()
	if needWarp {
		a.warp.Start()
	} else {
		a.warp.Stop()
	}
	switch {
	case !needTor:
		a.tor.Stop()
	case a.torSocks != "":
		if !a.tor.Enabled() {
			a.tor.UseExternal(a.torSocks)
		}
	case runtime.GOOS == "android":
		// На Android Tor запускает приложение (TorService) и передаёт его адрес в -tor-socks.
	case restartTor || !a.tor.Enabled():
		a.startTor()
	}
}

// routeSummary — что делает программа в текущем режиме (одна строка для главного экрана).
func routeSummary(s Settings) string {
	switch s.Route {
	case RouteDev:
		return "Через компьютер разработчика"
	case RouteDPI:
		return "Обход блокировок"
	case RouteTor:
		return "Весь трафик через Tor"
	case RouteWarp:
		return "Весь трафик через WARP (другой IP)"
	}
	switch s.Heavy {
	case HeavyWarp:
		return "Обход блокировок, при необходимости — WARP"
	case HeavyTor:
		return "Обход блокировок, при необходимости — Tor"
	}
	return "Обход блокировок, при необходимости — WARP или Tor"
}

// upstreamLines — состояние WARP и Tor для интерфейса: обычные строки и предупреждения.
func (a *App) upstreamLines() (lines, warns []string) {
	needW, needT := a.needs()
	if needW {
		switch ws, we := a.warp.Status(); ws {
		case "ready":
			lines = append(lines, "WARP подключён")
		case "starting":
			lines = append(lines, "WARP подключается…")
		case "error":
			lines = append(lines, "WARP не подключился")
			if we != "" {
				warns = append(warns, we)
			}
		}
	}
	if a.settings().Route == RouteDev && a.eng.Dev != nil {
		switch a.eng.Dev.State() {
		case "ready":
			lines = append(lines, "Разработчик на связи")
		case "down":
			lines = append(lines, "Разработчик недоступен — обычный режим")
		default:
			lines = append(lines, "Подключение к разработчику…")
		}
	}
	if needT {
		ts, tp, te := a.tor.Status()
		if te == "" {
			a.mu.Lock()
			te = a.torErr
			a.mu.Unlock()
		}
		switch ts {
		case "ready":
			lines = append(lines, "Tor подключён")
		case "starting":
			lines = append(lines, fmt.Sprintf("Tor подключается… %d%%", tp))
			if a.tor.Stalled() {
				warns = append(warns, StallHint)
			}
		default:
			if te != "" {
				lines = append(lines, "Tor не запущен")
				warns = append(warns, te)
			}
		}
	}
	return lines, warns
}

func (a *App) enable() error {
	a.mu.Lock()
	port, sys := a.s.Port, a.s.SysProxy
	a.mu.Unlock()
	if err := a.eng.Start(port); err != nil {
		return err
	}
	a.proxyErr = ""
	if sys {
		if err := SetSystemProxy(port); err != nil {
			a.proxyErr = err.Error()
			a.logf("Системный прокси не включён: %v", err)
		} else {
			a.logf("Системный прокси включён")
		}
	}
	a.startUpstreams(true)
	return nil
}

func (a *App) disable() {
	a.mu.Lock()
	port := a.s.Port
	a.mu.Unlock()
	UnsetSystemProxy(port)
	a.eng.Stop()
	a.tor.Stop()
	a.warp.Stop()
}

func (a *App) state() map[string]any {
	learned := a.eng.Learned()
	blocked := a.eng.Blocked()
	type item struct {
		Host     string `json:"host"`
		Strategy string `json:"strategy,omitempty"`
		Name     string `json:"name,omitempty"`
		Reason   string `json:"reason,omitempty"`
	}
	var ls, bs []item
	for h, s := range learned {
		ls = append(ls, item{Host: h, Strategy: s, Name: StratNames[s]})
	}
	for h, r := range blocked {
		bs = append(bs, item{Host: h, Reason: r})
	}
	sort.Slice(ls, func(i, j int) bool { return ls[i].Host < ls[j].Host })
	sort.Slice(bs, func(i, j int) bool { return bs[i].Host < bs[j].Host })
	kv := func(order []string, names map[string]string) []map[string]string {
		out := []map[string]string{}
		for _, k := range order {
			out = append(out, map[string]string{"id": k, "name": names[k]})
		}
		return out
	}
	upLines, upWarns := a.upstreamLines()
	summary := routeSummary(a.settings())
	ts, tp, te := a.tor.Status()
	ws, we := a.warp.Status()
	wep := a.warp.Endpoint()
	cur := a.settings()
	ads := map[string]any{"on": cur.AdBlock, "blocked": a.ads.Count(), "rules": a.ads.Rules()}
	askBridges, offer := a.askBridges(), a.shareOffer()
	dev := a.devState()
	a.mu.Lock()
	defer a.mu.Unlock()
	if te == "" {
		te = a.torErr
	}
	return map[string]any{
		"on":          a.eng.Running(),
		"settings":    a.s,
		"learned":     ls,
		"blocked":     bs,
		"strategies":  kv(AutoOrder, StratNames),
		"routes":      kv(routeIDs(), RouteNames),
		"heavies":     kv(heavyOrder, HeavyNames),
		"countries":   kv(torCountryOrder, TorCountries),
		"up_lines":    upLines,
		"up_warns":    upWarns,
		"summary":     summary,
		"warp":        map[string]any{"status": ws, "error": we, "endpoint": wep},
		"ads":         ads,
		"ask_bridges": askBridges,
		"dev":         dev,
		"share_offer": offer,
		"bridges":     kv(bridgeOrder, BridgeNames),
		"tor":         map[string]any{"status": ts, "progress": tp, "error": te},
		"active":      a.eng.conns.Load(),
		"total":       a.eng.total.Load(),
		"proxy_err":   a.proxyErr,
		"os":          runtime.GOOS,
		"version":     appVersion,
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// guard: проверка Host (защита от DNS-rebinding) и токена (защита от CSRF).
func (a *App) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Host != a.addr || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Token")), []byte(a.token)) != 1 {
			http.Error(w, "forbidden", 403)
			return
		}
		next(w, r)
	}
}

func (a *App) routes(mux *http.ServeMux, shutdown func()) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Host != a.addr || r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data: https://flagcdn.com")
		_, _ = w.Write(indexHTML)
	})
	// Картинки интерфейса (планета, эмблема).
	for path, data := range map[string][]byte{"/planet-on.png": planetOnPNG, "/planet-off.png": planetOffPNG, "/logo.png": logoWebPNG, "/brand.png": brandPNG} {
		data := data
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if r.Host != a.addr {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Cache-Control", "max-age=86400")
			_, _ = w.Write(data)
		})
	}
	// /ping — чтобы повторно запущенная копия узнала, что «Обход» уже работает.
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		if r.Host != a.addr {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("obhod"))
	})
	mux.HandleFunc("/api/show", a.guard(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		show := a.showUI
		a.mu.Unlock()
		if show != nil {
			go show()
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("/api/ip", a.guard(func(w http.ResponseWriter, r *http.Request) {
		ip, cc, err := publicIP()
		if err != nil {
			writeJSON(w, 200, map[string]string{"ip": "", "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"ip": ip, "country": cc})
	}))
	mux.HandleFunc("/api/state", a.guard(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, a.state()) }))
	mux.HandleFunc("/api/logs", a.guard(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		l := append([]string(nil), a.logs...)
		a.mu.Unlock()
		writeJSON(w, 200, l)
	}))
	mux.HandleFunc("/api/toggle", a.guard(func(w http.ResponseWriter, r *http.Request) {
		if a.eng.Running() {
			a.disable()
		} else if err := a.enable(); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, a.state())
	}))
	mux.HandleFunc("/api/settings", a.guard(func(w http.ResponseWriter, r *http.Request) {
		var s Settings
		if json.NewDecoder(r.Body).Decode(&s) != nil {
			writeJSON(w, 400, map[string]string{"error": "неверные настройки"})
			return
		}
		if err := a.applySettings(s); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, a.state())
	}))
	mux.HandleFunc("/api/test", a.guard(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Host string `json:"host"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		res, err := a.eng.TestHost(req.Host, false)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, res)
	}))
	mux.HandleFunc("/api/forget", a.guard(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Host string `json:"host"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		a.eng.Forget(req.Host)
		writeJSON(w, 200, a.state())
	}))
	// Передача мостов в локальной сети и первое предложение получить мосты.
	mux.HandleFunc("/api/share/discover", a.guard(func(w http.ResponseWriter, r *http.Request) {
		if a.share == nil {
			writeJSON(w, 200, []ShareDevice{})
			return
		}
		writeJSON(w, 200, a.share.Discover(2500*time.Millisecond))
	}))
	mux.HandleFunc("/api/share/send", a.guard(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IP string `json:"ip"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if err := a.sendBridges(req.IP); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("/api/share/answer", a.guard(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     string `json:"id"`
			Accept bool   `json:"accept"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		a.answerShare(req.ID, req.Accept)
		writeJSON(w, 200, a.state())
	}))
	// Режим разработчика (только сборка разработчика; в пользовательской — ответы «недоступно»).
	devErr := func(w http.ResponseWriter, err error) bool {
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return true
		}
		return false
	}
	mux.HandleFunc("/api/dev/unlock", a.guard(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if err := a.devUnlock(req.Password); err != nil {
			time.Sleep(time.Second) // перебор паролей — медленно
			devErr(w, err)
			return
		}
		writeJSON(w, 200, a.state())
	}))
	mux.HandleFunc("/api/dev/lock", a.guard(func(w http.ResponseWriter, r *http.Request) {
		a.devLock()
		writeJSON(w, 200, a.state())
	}))
	mux.HandleFunc("/api/dev/share", a.guard(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			On bool `json:"on"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if devErr(w, a.devSetShare(req.On)) {
			return
		}
		writeJSON(w, 200, a.state())
	}))
	mux.HandleFunc("/api/dev/key", a.guard(func(w http.ResponseWriter, r *http.Request) {
		if a.dev == nil || !a.settings().DevMode {
			devErr(w, errors.New("режим разработчика выключен"))
			return
		}
		k, err := a.dev.ExportKey()
		if devErr(w, err) {
			return
		}
		writeJSON(w, 200, map[string]string{"key": k})
	}))
	mux.HandleFunc("/api/dev/key/import", a.guard(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Text string `json:"text"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if a.dev == nil || !a.settings().DevMode {
			devErr(w, errors.New("режим разработчика выключен"))
			return
		}
		if devErr(w, a.dev.ImportKey(req.Text)) {
			return
		}
		writeJSON(w, 200, a.state())
	}))
	mux.HandleFunc("/api/dev/key/save", a.guard(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Where string `json:"where"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if a.dev == nil || !a.settings().DevMode {
			devErr(w, errors.New("режим разработчика выключен"))
			return
		}
		var paths []string
		var err error
		if req.Where == "cloud" {
			paths, err = a.dev.SaveKeyToCloud()
		} else {
			home, _ := os.UserHomeDir()
			p := filepath.Join(home, "AristocratNET-ключ-разработчика.txt")
			if err = a.dev.SaveKey(p); err == nil {
				paths = []string{p}
			}
		}
		if devErr(w, err) {
			return
		}
		writeJSON(w, 200, map[string]any{"paths": paths})
	}))
	mux.HandleFunc("/api/dev/journal", a.guard(func(w http.ResponseWriter, r *http.Request) {
		if a.dev == nil || !a.settings().DevMode {
			devErr(w, errors.New("режим разработчика выключен"))
			return
		}
		if r.Method == http.MethodPost {
			a.dev.ClearJournal()
		}
		writeJSON(w, 200, map[string]string{"text": a.dev.JournalText()})
	}))
	mux.HandleFunc("/api/hide", a.guard(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		hide := a.hideUI
		a.mu.Unlock()
		writeJSON(w, 200, map[string]bool{"ok": hide != nil})
		if hide != nil {
			go hide()
		}
	}))
	mux.HandleFunc("/api/asked", a.guard(func(w http.ResponseWriter, r *http.Request) {
		a.setBridgesAsked()
		writeJSON(w, 200, a.state())
	}))
	mux.HandleFunc("/api/quit", a.guard(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]bool{"ok": true})
		go func() { time.Sleep(200 * time.Millisecond); shutdown() }()
	}))
}

func defaultDataDir() string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = "."
	}
	return filepath.Join(base, appName)
}

func main() {
	var (
		noBrowser  = flag.Bool("no-browser", false, "не открывать окно")
		uiPort     = flag.Int("ui-port", 47831, "порт интерфейса")
		headless   = flag.Bool("headless", false, "без интерфейса: только прокси (Android, сервер, роутер)")
		dataFlag   = flag.String("data", "", "папка данных")
		portFlag   = flag.Int("port", 0, "порт прокси (по умолчанию из настроек, 8881)")
		routeFlag  = flag.String("route", "", "маршрут: auto | dpi | warp | tor")
		heavyFlag  = flag.String("heavy", "", "запасной путь в режиме auto: warp-tor | warp | tor")
		torCountry = flag.String("tor-country", "", "страна выхода из Tor: de, nl, us… или any")
		torPhase   = flag.Int("tor-phase", 0, "этап автовыбора мостов: 0 — snowflake, 1 — obfs4 и meek (для -write-torrc)")
		geoipDir   = flag.String("geoip-dir", "", "папка с файлами geoip/geoip6 (Android)")
		keepLocal  = flag.String("keep-local", "", "российские и казахстанские сайты напрямую: on | off")
		geoTor     = flag.String("geo-tor", "", "в России Spotify и подобное через Tor: on | off")
		adblock    = flag.String("adblock", "", "блокировка рекламы: on | off")
		deviceName = flag.String("device-name", "", "имя устройства для журнала разработчика (Android)")
		torLog     = flag.String("tor-log", "", "журнал внешнего Tor (Android): torrc пишет его, ядро читает")
		stratFlag  = flag.String("strategy", "", "метод обхода DPI: auto | tlsrec | split | ...")
		dohFlag    = flag.String("doh", "", "DoH: cloudflare | google | quad9")
		torSocks   = flag.String("tor-socks", "", "адрес уже запущенного Tor SOCKS (Android: TorService)")
		writeTorrc = flag.String("write-torrc", "", "записать torrc в файл и выйти (для Android)")
		bridges    = flag.String("bridges", "", "мосты: snowflake | webtunnel | obfs4 | meek | custom | none")
		customFile = flag.String("custom-bridges", "", "файл со своими мостами")
		ptConfig   = flag.String("pt-config", "", "путь к pt_config.json")
		lyrebird   = flag.String("lyrebird", "", "путь к lyrebird")
		ptSocks    = flag.String("pt-socks", "", "запущенные транспорты Tor (Android): obfs4=127.0.0.1:port,webtunnel=…")
		version    = flag.Bool("version", false, "версия")
		minimized  = flag.Bool("minimized", false, "запуститься свёрнутым в трей")
	)
	flag.Parse()
	if *version {
		fmt.Println(appName, appVersion)
		return
	}

	a := &App{dir: *dataFlag}
	if a.dir == "" {
		a.dir = defaultDataDir()
	}
	a.load()
	if *portFlag != 0 {
		a.s.Port = *portFlag
	}
	if *routeFlag != "" {
		a.s.Route = *routeFlag
	}
	if *heavyFlag != "" {
		a.s.Heavy = *heavyFlag
	}
	if *keepLocal != "" {
		a.s.KeepLocal = *keepLocal == "on"
	}
	if *adblock != "" {
		a.s.AdBlock = *adblock == "on"
	}
	if *geoTor != "" {
		a.s.GeoTor = *geoTor == "on"
	}
	if *stratFlag != "" {
		a.s.Mode = *stratFlag
	}
	if *dohFlag != "" {
		a.s.DoH = *dohFlag
	}
	if *bridges != "" {
		a.s.Bridges = *bridges
	}
	if *torCountry == "any" {
		a.s.TorCountry = ""
	} else if *torCountry != "" {
		a.s.TorCountry = *torCountry
	}
	if *customFile != "" {
		if b, err := os.ReadFile(*customFile); err == nil {
			a.s.CustomBridges = string(b)
		}
	}
	a.s.normalize()

	// Android: приложение просит собрать torrc для TorService.
	if *writeTorrc != "" {
		custom := a.s.CustomBridges
		if a.s.Bridges == "custom" || a.s.Bridges == "auto" {
			custom = rankBridges(custom, nil, func(f string, args ...any) { fmt.Printf(f+"\n", args...) })
		}
		torrc, err := BuildTorrc(TorOptions{Bridges: a.s.Bridges, Custom: custom, SocksAddr: torSocksAddr,
			PTConfigPath: *ptConfig, LyrebirdPath: *lyrebird, ForAndroid: true, LogFile: *torLog,
			ExitCountry: a.s.TorCountry, GeoIPDir: *geoipDir, AutoPhase: *torPhase, PTSocks: parsePTSocks(*ptSocks),
			ClientAuthDir: writeDevClientAuth(filepath.Join(a.dir, "tor-auth"))})
		if err != nil {
			fmt.Fprintln(os.Stderr, "torrc:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*writeTorrc, []byte(torrc), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	b := make([]byte, 16)
	_, _ = rand.Read(b)
	a.token = hex.EncodeToString(b)
	a.res = NewResolver(a.s.DoH, a.logf)
	a.tor = NewTor(a.logf)
	a.eng = NewEngine(a.res, a.logf)
	a.eng.Tor = a.tor
	a.warp = NewWarp(a.dir, a.logf)
	a.warp.DialTLS = a.eng.dialTLSBypass
	go a.watchTorBridges()
	a.eng.Warp = a.warp
	a.geo = &GeoIP{}
	a.eng.Local = &Local{
		Geo:         a.geo,
		Enabled:     func() bool { return a.settings().KeepLocal },
		UserCountry: a.userCountry,
		Resolve:     a.res.Lookup,
	}
	// «Через разработчика» (если в сборке есть код подключения).
	if dl := NewDevLink(a.tor, a.dir, a.logf); dl != nil {
		dev := *deviceName
		if dev == "" {
			dev, _ = os.Hostname()
		}
		dl.Info = func() string {
			ip, cc, _ := publicIP()
			return devInfo(dev, ip, cc, myCity(ip))
		}
		a.eng.Dev = dl
	}
	a.ads = NewAdBlock(a.dir, a.logf)
	a.ads.Enabled = func() bool { return a.settings().AdBlock }
	a.ads.Fetch = httpFetch(a.eng.dialTLSBypass)
	a.eng.Ads = a.ads
	go a.ads.Run()
	go a.loadGeoIP(*geoipDir)
	go a.detectCountry()
	a.eng.BlockQUIC = true
	a.torSocks = *torSocks
	a.eng.Mode.Store(a.s.Mode)
	a.eng.Route.Store(a.s.Route)
	a.eng.SetLearned(a.s.Learned)
	a.eng.onLearn = a.save

	var once sync.Once
	var srv *http.Server
	shutdown := func() {
		once.Do(func() {
			a.devStop()
			a.disable()
			a.save()
			if srv != nil {
				_ = srv.Close()
			}
		})
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	if *headless {
		a.s.SysProxy = false
		pidFile := filepath.Join(a.dir, "core.pid")
		_ = os.MkdirAll(a.dir, 0o700)
		_ = os.WriteFile(pidFile, []byte(fmt.Sprint(os.Getpid())), 0o600)
		defer os.Remove(pidFile)
		if err := a.eng.Start(a.s.Port); err != nil {
			log.Fatal(err)
		}
		a.startUpstreams(true)
		if *torLog != "" && a.torSocks != "" {
			go tailTorLog(*torLog, a.tor, a.logf)
		}
		fmt.Printf("%s %s: прокси HTTP/SOCKS5 на 127.0.0.1:%d, маршрут %s (Ctrl+C — выход)\n", appName, appVersion, a.s.Port, a.s.Route)
		go func() {
			for {
				time.Sleep(time.Second)
				a.mu.Lock()
				for _, l := range a.logs {
					fmt.Println(l)
				}
				a.logs = nil
				a.mu.Unlock()
			}
		}()
		<-sig
		shutdown()
		return
	}

	// Одна копия программы: если «Обход» уже запущен (окно просто закрыли, а он работает в фоне),
	// открываем его окно и выходим, вместо того чтобы запускать вторую копию.
	tokenFile := filepath.Join(a.dir, "ui-token")
	if runningInstance(*uiPort, tokenFile) {
		fmt.Println("«Обход» уже запущен — показываю его окно")
		return
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *uiPort))
	fixedPort := err == nil
	if err != nil {
		if ln, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			log.Fatal(err)
		}
	}
	a.addr = ln.Addr().String()
	if fixedPort {
		_ = os.MkdirAll(a.dir, 0o700)
		_ = os.WriteFile(tokenFile, []byte(a.token), 0o600)
	}
	srv = &http.Server{ReadHeaderTimeout: 10 * time.Second}
	mux := http.NewServeMux()
	a.routes(mux, shutdown)
	srv.Handler = mux
	go func() { <-sig; shutdown() }()

	a.share = NewShare(a.logf)
	a.share.Listen()
	a.devInit()
	UnsetSystemProxy(a.s.Port) // на случай аварийного завершения прошлой сессии
	if a.s.AutoStart {
		if err := a.enable(); err != nil {
			a.logf("Не удалось включить: %v", err)
		}
	}

	url := fmt.Sprintf("http://%s/#%s", a.addr, a.token)
	fmt.Printf("%s %s — интерфейс: %s\n", appName, appVersion, url)
	served := make(chan struct{})
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Println(err)
		}
		close(served)
	}()
	// Окно и значок в трее; возвращается после выхода из программы.
	runDesktopUI(a, url, !*noBrowser && !*minimized, shutdown, served)
	shutdown()
}

var ipCache struct {
	sync.Mutex
	ip, country, city string
	exp               time.Time
}

// publicIP — реальный внешний IP и страна (запрос идёт напрямую, мимо прокси и Tor).
func publicIP() (string, string, error) {
	ipCache.Lock()
	defer ipCache.Unlock()
	if ipCache.ip != "" && time.Now().Before(ipCache.exp) {
		return ipCache.ip, ipCache.country, nil
	}
	cl := &http.Client{Timeout: 6 * time.Second, Transport: &http.Transport{Proxy: nil}}
	get := func(u string) ([]byte, error) {
		resp, err := cl.Get(u)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	}
	var ip, cc, city string
	var lastErr error
	// Сервисы, сразу отдающие IP и страну.
	for _, u := range []struct{ url, ipKey, ccKey string }{
		{"https://api.country.is/", "ip", "country"},
		{"https://ipwho.is/", "ip", "country_code"},
		{"https://ipinfo.io/json", "ip", "country"},
	} {
		b, err := get(u.url)
		if err != nil {
			lastErr = err
			continue
		}
		var m map[string]any
		if json.Unmarshal(b, &m) != nil {
			continue
		}
		ip, _ = m[u.ipKey].(string)
		cc, _ = m[u.ccKey].(string)
		city, _ = m["city"].(string)
		if net.ParseIP(ip) != nil {
			break
		}
		ip = ""
	}
	// Запасной вариант — только IP.
	if ip == "" {
		for _, u := range []string{"https://api.ipify.org", "https://ipv4.icanhazip.com"} {
			if b, err := get(u); err == nil && net.ParseIP(strings.TrimSpace(string(b))) != nil {
				ip = strings.TrimSpace(string(b))
				break
			} else if err != nil {
				lastErr = err
			}
		}
	}
	if ip == "" {
		if lastErr == nil {
			lastErr = fmt.Errorf("сервис определения IP не ответил")
		}
		return "", "", lastErr
	}
	cc = strings.ToUpper(strings.TrimSpace(cc))
	if len(cc) != 2 {
		cc = ""
	}
	ipCache.ip, ipCache.country, ipCache.city, ipCache.exp = ip, cc, city, time.Now().Add(2*time.Minute)
	return ip, cc, nil
}

// runningInstance: если «Обход» уже запущен (окно закрыто, программа в трее), просит его показать окно.
func runningInstance(uiPort int, tokenFile string) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", uiPort)
	cl := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := cl.Get("http://" + addr + "/ping")
	if err != nil {
		return false
	}
	b := make([]byte, 16)
	n, _ := resp.Body.Read(b)
	resp.Body.Close()
	if string(b[:n]) != "obhod" {
		return false
	}
	tok, err := os.ReadFile(tokenFile)
	if err != nil || len(tok) == 0 {
		return false
	}
	token := strings.TrimSpace(string(tok))
	req, _ := http.NewRequest("POST", "http://"+addr+"/api/show", strings.NewReader("{}"))
	req.Header.Set("X-Token", token)
	if r2, err := cl.Do(req); err == nil {
		r2.Body.Close()
		if r2.StatusCode == 200 {
			return true
		}
	}
	// Старая версия без /api/show — просто открываем её интерфейс.
	openWindow(fmt.Sprintf("http://%s/#%s", addr, token))
	return true
}

// syncDir копирует файлы из src в dst (без подпапок), если они отличаются размером или отсутствуют.
func syncDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	ents, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		to := filepath.Join(dst, e.Name())
		if st, err := os.Stat(to); err == nil && st.Size() == info.Size() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(to, b, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func fileExists(p string) bool { st, err := os.Stat(p); return err == nil && !st.IsDir() }

// openWindow открывает интерфейс «как приложение» в Edge/Chrome, иначе в браузере по умолчанию.
func openWindow(url string) {
	args := []string{"--app=" + url, "--window-size=460,820", "--new-window", "--no-proxy-server"}
	var cands []string
	switch runtime.GOOS {
	case "windows":
		pf, pf86, local := os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LocalAppData")
		cands = []string{
			filepath.Join(pf86, `Microsoft\Edge\Application\msedge.exe`),
			filepath.Join(pf, `Microsoft\Edge\Application\msedge.exe`),
			filepath.Join(pf, `Google\Chrome\Application\chrome.exe`),
			filepath.Join(pf86, `Google\Chrome\Application\chrome.exe`),
			filepath.Join(local, `Google\Chrome\Application\chrome.exe`),
		}
	case "darwin":
		cands = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		}
	default:
		for _, n := range []string{"google-chrome", "chromium", "chromium-browser", "microsoft-edge"} {
			if p, err := exec.LookPath(n); err == nil {
				cands = append(cands, p)
			}
		}
	}
	for _, c := range cands {
		if fileExists(c) {
			if exec.Command(c, args...).Start() == nil {
				return
			}
		}
	}
	openLink(url)
}

// openLink открывает ссылку программой по умолчанию (браузер, Telegram для tg://).
func openLink(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
		hideWindow(cmd)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

// Бот Tor Project, который присылает мосты.
const bridgesBotURL = "https://t.me/GetBridgesBot"

// parsePTSocks разбирает «obfs4=127.0.0.1:1234,webtunnel=127.0.0.1:1235».
func parsePTSocks(v string) map[string]string {
	m := map[string]string{}
	for _, kv := range strings.Split(v, ",") {
		if k, a, ok := strings.Cut(strings.TrimSpace(kv), "="); ok && k != "" && a != "" {
			m[k] = a
		}
	}
	return m
}

// askBridges — показать при первом запуске предложение получить мосты Tor.
func (a *App) askBridges() bool {
	st := a.settings()
	return !st.BridgesAsked && len(splitBridgeLines(st.CustomBridges)) == 0
}

func (a *App) setBridgesAsked() {
	a.mu.Lock()
	a.s.BridgesAsked = true
	a.mu.Unlock()
	a.save()
}

func (a *App) shareOffer() *ShareOffer {
	if a.share == nil {
		return nil
	}
	return a.share.Offer()
}

// sendBridges — отправить свои мосты на устройство в локальной сети.
func (a *App) sendBridges(ip string) error {
	if a.share == nil {
		return errors.New("передача мостов недоступна")
	}
	text := strings.Join(splitBridgeLines(a.settings().CustomBridges), "\n")
	if text == "" {
		return errors.New("сначала добавьте свои мосты")
	}
	return a.share.Send(ip, text)
}

// answerShare — пользователь принял или отклонил присланные мосты.
func (a *App) answerShare(id string, accept bool) {
	if a.share == nil {
		return
	}
	text, ok := a.share.Take(id)
	if !ok || !accept {
		return
	}
	s := a.settings()
	s.CustomBridges = text
	if s.Bridges != "auto" && s.Bridges != "custom" {
		s.Bridges = "custom"
	}
	if err := a.applySettings(s); err != nil {
		a.logf("Не удалось сохранить мосты: %v", err)
		return
	}
	a.setBridgesAsked()
	a.logf("Приняты мосты: %d", len(splitBridgeLines(text)))
}

// relIfSet — путь для torrc относительно папки tor (rel), если abs задан.
func relIfSet(abs, rel string) string {
	if abs == "" {
		return ""
	}
	return rel
}

// routeIDs — режимы работы для интерфейса («Через разработчика» — если в сборке есть код подключения).
func routeIDs() []string {
	ids := []string{RouteAuto, RouteDPI, RouteWarp, RouteTor}
	if devAvailable() {
		ids = append(ids, RouteDev)
	}
	return ids
}

var cityCache struct {
	sync.Mutex
	ip, city string
	exp      time.Time
}

// myCity — город по настоящему IP (для журнала разработчика); кэшируется на час.
func myCity(ip string) string {
	cityCache.Lock()
	defer cityCache.Unlock()
	if cityCache.ip == ip && time.Now().Before(cityCache.exp) {
		return cityCache.city
	}
	city := ""
	ipCache.Lock()
	if ipCache.ip == ip {
		city = ipCache.city
	}
	ipCache.Unlock()
	if city == "" {
		cl := &http.Client{Timeout: 6 * time.Second, Transport: &http.Transport{Proxy: nil}}
		if resp, err := cl.Get("https://ipwho.is/"); err == nil {
			var m map[string]any
			_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&m)
			resp.Body.Close()
			city, _ = m["city"].(string)
		}
	}
	cityCache.ip, cityCache.city, cityCache.exp = ip, city, time.Now().Add(time.Hour)
	return city
}
