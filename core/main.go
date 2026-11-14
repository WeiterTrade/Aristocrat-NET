// Обход — локальный обход блокировок без VPN-подписок и своих серверов.
//
//   - Сначала соединение идёт напрямую с обходом DPI (дробление ClientHello, disorder), DNS — через DoH.
//   - Если сайт заблокирован по IP или обход DPI не помог — автоматически через Tor (с мостами).
//
// На ПК программа работает как системный прокси с веб-интерфейсом,
// на Android — как ядро за системным VPN (запускается приложением с флагом -headless).
package main

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
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
	"strings"
	"sync"
	"syscall"
	"time"
)

const appName = "Obhod"

var appVersion = "0.6.1" // перезаписывается при сборке: -ldflags "-X main.appVersion=..."

const torSocksAddr = "127.0.0.1:9077"

//go:embed ui/index.html
var indexHTML []byte

//go:embed ui/planet-on.png
var planetOnPNG []byte

//go:embed ui/planet-off.png
var planetOffPNG []byte

//go:embed ui/logo.png
var logoWebPNG []byte

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
	Learned       map[string]string `json:"learned"`
	Ver           int               `json:"ver"`
}

const settingsVer = 3

func defaultSettings() Settings {
	return Settings{Port: 8881, Mode: "auto", Route: RouteAuto, Heavy: HeavyWarpTor, Bridges: "auto",
		SysProxy: true, DoH: "cloudflare", AutoStart: true}
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
	warp     *Warp
	torSocks string // внешний Tor (Android)
	token    string
	addr     string
	logs     []string
	proxyErr string
	torErr   string
	showUI   func() // показать окно программы (нативное окно на Windows, браузер на Linux)
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
	if a.s.Ver < 3 {
		a.s.Heavy = HeavyWarpTor
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

// startTor запускает встроенный tor (на ПК).
func (a *App) startTor() {
	a.mu.Lock()
	bridges, custom, country := a.s.Bridges, a.s.CustomBridges, a.s.TorCountry
	a.mu.Unlock()
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
	torrc, err := BuildTorrc(TorOptions{
		Bridges: bridges, Custom: custom, SocksAddr: socks, DataDir: "tor-data",
		PTConfigPath: paths.PTConfig, PTDir: ptDir, WorkDir: a.dir, GeoIPDir: geoDir, ExitCountry: country,
	})
	if err != nil {
		a.torErr = err.Error()
		a.logf("Tor: %v", err)
		return
	}
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
	case RouteWarp:
		return true, false
	case RouteTor:
		return false, true
	case RouteDPI:
		return false, false
	}
	return s.Heavy != HeavyTor, s.Heavy != HeavyWarp
}

// startUpstreams запускает или останавливает WARP и Tor под текущие настройки.
// restartTor — перезапустить Tor (сменились мосты).
func (a *App) startUpstreams(restartTor bool) {
	a.mu.Lock()
	needWarp, needTor := a.s.needs()
	a.mu.Unlock()
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
	needW, needT := a.settings().needs()
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
	a.mu.Lock()
	defer a.mu.Unlock()
	if te == "" {
		te = a.torErr
	}
	return map[string]any{
		"on":         a.eng.Running(),
		"settings":   a.s,
		"learned":    ls,
		"blocked":    bs,
		"strategies": kv(AutoOrder, StratNames),
		"routes":     kv([]string{RouteAuto, RouteDPI, RouteWarp, RouteTor}, RouteNames),
		"heavies":    kv(heavyOrder, HeavyNames),
		"countries":  kv(torCountryOrder, TorCountries),
		"up_lines":   upLines,
		"up_warns":   upWarns,
		"summary":    summary,
		"warp":       map[string]any{"status": ws, "error": we, "endpoint": wep},
		"bridges":    kv(bridgeOrder, BridgeNames),
		"tor":        map[string]any{"status": ts, "progress": tp, "error": te},
		"active":     a.eng.conns.Load(),
		"total":      a.eng.total.Load(),
		"proxy_err":  a.proxyErr,
		"os":         runtime.GOOS,
		"version":    appVersion,
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
	for path, data := range map[string][]byte{"/planet-on.png": planetOnPNG, "/planet-off.png": planetOffPNG, "/logo.png": logoWebPNG} {
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
		geoipDir   = flag.String("geoip-dir", "", "папка с файлами geoip/geoip6 (Android)")
		torLog     = flag.String("tor-log", "", "журнал внешнего Tor (Android): torrc пишет его, ядро читает")
		stratFlag  = flag.String("strategy", "", "метод обхода DPI: auto | tlsrec | split | ...")
		dohFlag    = flag.String("doh", "", "DoH: cloudflare | google | quad9")
		torSocks   = flag.String("tor-socks", "", "адрес уже запущенного Tor SOCKS (Android: TorService)")
		writeTorrc = flag.String("write-torrc", "", "записать torrc в файл и выйти (для Android)")
		bridges    = flag.String("bridges", "", "мосты: snowflake | webtunnel | obfs4 | meek | custom | none")
		customFile = flag.String("custom-bridges", "", "файл со своими мостами")
		ptConfig   = flag.String("pt-config", "", "путь к pt_config.json")
		lyrebird   = flag.String("lyrebird", "", "путь к lyrebird")
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
		torrc, err := BuildTorrc(TorOptions{Bridges: a.s.Bridges, Custom: a.s.CustomBridges, SocksAddr: torSocksAddr,
			PTConfigPath: *ptConfig, LyrebirdPath: *lyrebird, ForAndroid: true, LogFile: *torLog,
			ExitCountry: a.s.TorCountry, GeoIPDir: *geoipDir})
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
	a.eng.Warp = a.warp
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
	ip, country string
	exp         time.Time
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
	var ip, cc string
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
	ipCache.ip, ipCache.country, ipCache.exp = ip, cc, time.Now().Add(2*time.Minute)
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
