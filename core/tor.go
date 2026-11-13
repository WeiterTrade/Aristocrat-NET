package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Типы мостов. В РФ/РК прямое подключение к Tor заблокировано, поэтому по умолчанию — snowflake.
var BridgeNames = map[string]string{
	"snowflake": "Snowflake (рекомендуется)",
	"obfs4":     "obfs4",
	"meek":      "meek (Azure)",
	"custom":    "Свои мосты",
	"none":      "Без мостов",
}

// WebTunnel-мостов в Tor нет встроенных — их получают в @GetBridgesBot и вставляют в «Свои мосты».
var bridgeOrder = []string{"snowflake", "obfs4", "meek", "custom", "none"}

// PTConfig — формат pt_config.json из Tor Expert Bundle.
type PTConfig struct {
	PluggableTransports map[string]string   `json:"pluggableTransports"`
	Bridges             map[string][]string `json:"bridges"`
}

func LoadPTConfig(path string) (*PTConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c PTConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("pt_config.json: %w", err)
	}
	return &c, nil
}

// TorOptions — что нужно для сборки torrc.
type TorOptions struct {
	Bridges      string // snowflake | webtunnel | obfs4 | meek | custom | none
	Custom       string // свои строки мостов, по одной в строке
	SocksAddr    string // 127.0.0.1:9077
	DataDir      string
	PTConfigPath string
	PTDir        string // путь к папке с lyrebird ОТНОСИТЕЛЬНО рабочей папки tor (без пробелов!)
	WorkDir      string // рабочая папка процесса tor
	LyrebirdPath string // явный путь к lyrebird (Android: liblyrebird.so)
	GeoIPDir     string
	ForAndroid   bool // DataDirectory и порты управления задаёт TorService
}

var reBridgeTransport = regexp.MustCompile(`^\s*(?:Bridge\s+)?([a-z_0-9]+)\s`)

// BuildTorrc собирает конфигурацию tor.
func BuildTorrc(o TorOptions) (string, error) {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }

	w("SOCKSPort %s", o.SocksAddr)
	w("ClientOnly 1")
	w("AvoidDiskWrites 1")
	if !o.ForAndroid {
		w("DataDirectory %s", o.DataDir)
		w("Log notice stdout")
		if o.GeoIPDir != "" {
			for _, g := range []struct{ opt, file string }{{"GeoIPFile", "geoip"}, {"GeoIPv6File", "geoip6"}} {
				p := filepath.Join(o.GeoIPDir, g.file)
				check := p
				if !filepath.IsAbs(p) && o.WorkDir != "" {
					check = filepath.Join(o.WorkDir, p) // путь относительно рабочей папки tor
				}
				if fileExists(check) {
					w("%s %s", g.opt, p)
				}
			}
		}
	}
	if o.Bridges == "none" {
		return b.String(), nil
	}

	var lines []string
	if o.Bridges == "custom" {
		for _, l := range strings.Split(o.Custom, "\n") {
			l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "Bridge "))
			if l != "" && !strings.HasPrefix(l, "#") {
				lines = append(lines, l)
			}
		}
		if len(lines) == 0 {
			return "", errors.New("не указаны свои мосты")
		}
	}

	var pt *PTConfig
	if o.PTConfigPath != "" {
		var err error
		if pt, err = LoadPTConfig(o.PTConfigPath); err != nil {
			return "", err
		}
	}
	if o.Bridges != "custom" {
		if pt == nil {
			return "", errors.New("нет pt_config.json со встроенными мостами")
		}
		lines = pt.Bridges[o.Bridges]
		if o.Bridges == "meek" && len(lines) == 0 {
			lines = pt.Bridges["meek-azure"]
		}
		if len(lines) == 0 {
			return "", fmt.Errorf("встроенных мостов типа %s нет — получите мосты в Telegram-боте @GetBridgesBot "+
				"и вставьте их в «Свои мосты»", o.Bridges)
		}
	}

	// Какие транспорты нужны.
	need := map[string]bool{}
	for _, l := range lines {
		if m := reBridgeTransport.FindStringSubmatch(l); m != nil && !looksLikeAddr(m[1]) {
			need[m[1]] = true
		}
	}

	// В torrc путь в ClientTransportPlugin не может содержать пробелы,
	// поэтому tor запускается из своей папки, а lyrebird указывается относительно неё.
	ptDir := o.PTDir
	if ptDir == "" && o.PTConfigPath != "" {
		ptDir = filepath.Dir(o.PTConfigPath)
	}
	plugins := 0
	if pt != nil {
		for _, line := range pt.PluggableTransports {
			// Строка вида: ClientTransportPlugin meek_lite,obfs4,... exec ${pt_path}lyrebird
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			used := false
			for _, t := range strings.Split(fields[1], ",") {
				if need[t] {
					used = true
				}
			}
			if !used {
				continue
			}
			if o.LyrebirdPath != "" {
				// Android: все транспорты (obfs4, meek, snowflake, webtunnel) даёт один lyrebird,
				// он лежит в nativeLibraryDir под именем liblyrebird.so. Аргументы после пути
				// (например, у conjure) отбрасываем — такие транспорты lyrebird не поддерживает.
				ts := []string{}
				for _, t := range strings.Split(fields[1], ",") {
					if lyrebirdTransports[t] {
						ts = append(ts, t)
					}
				}
				if len(ts) == 0 {
					continue
				}
				line = "ClientTransportPlugin " + strings.Join(ts, ",") + " exec " + o.LyrebirdPath
			} else {
				line = strings.ReplaceAll(line, "${pt_path}", ptDir+string(filepath.Separator))
				if runtime.GOOS == "windows" {
					line = fixWindowsExe(line, o.WorkDir)
				}
			}
			w("%s", line)
			plugins++
		}
	}
	if plugins == 0 && len(need) > 0 {
		if o.LyrebirdPath == "" {
			return "", errors.New("не найден lyrebird для мостов")
		}
		names := make([]string, 0, len(need))
		for t := range need {
			names = append(names, t)
		}
		w("ClientTransportPlugin %s exec %s", strings.Join(names, ","), o.LyrebirdPath)
	}
	w("UseBridges 1")
	for _, l := range lines {
		w("Bridge %s", strings.TrimPrefix(l, "Bridge "))
	}
	return b.String(), nil
}

// Транспорты, которые умеет lyrebird ≥ 0.6.
var lyrebirdTransports = map[string]bool{"meek_lite": true, "obfs2": true, "obfs3": true, "obfs4": true,
	"scramblesuit": true, "webtunnel": true, "snowflake": true}

func looksLikeAddr(s string) bool { return strings.ContainsAny(s, ".:[") }

// fixWindowsExe: в pt_config.json для Windows путь бывает без .exe.
func fixWindowsExe(line, baseDir string) string {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return line
	}
	exe := fields[3]
	if !filepath.IsAbs(exe) {
		exe = filepath.Join(baseDir, exe)
	}
	if !strings.HasSuffix(strings.ToLower(fields[3]), ".exe") && fileExists(exe+".exe") {
		return strings.Replace(line, fields[3], fields[3]+".exe", 1)
	}
	return line
}

// ---------------------------------------------------------------------------

// Tor управляет процессом tor (ПК) или использует внешний SOCKS (Android: TorService).
type Tor struct {
	mu       sync.Mutex
	cmd      *exec.Cmd
	external bool
	socks    string
	status   string // off | starting | ready | error
	progress int
	errMsg   string
	logf     func(string, ...any)
	ready    chan struct{}
}

func NewTor(logf func(string, ...any)) *Tor {
	return &Tor{status: "off", logf: logf, ready: make(chan struct{})}
}

// UseExternal — Tor запущен кем-то другим (TorService на Android).
func (t *Tor) UseExternal(socks string) {
	t.mu.Lock()
	t.external, t.socks, t.status, t.progress = true, socks, "starting", 0
	t.ready = make(chan struct{})
	t.mu.Unlock()
	go t.watchExternal()
}

// watchExternal считает внешний Tor готовым, когда через него открывается соединение.
func (t *Tor) watchExternal() {
	for i := 0; ; i++ {
		t.mu.Lock()
		if !t.external || t.status == "off" {
			t.mu.Unlock()
			return
		}
		t.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		c, err := socksDial(ctx, t.socks, "check.torproject.org", 443)
		cancel()
		if err == nil {
			c.Close()
			t.setReady()
			return
		}
		time.Sleep(3 * time.Second)
	}
}

func (t *Tor) setReady() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.status != "ready" {
		t.status, t.progress = "ready", 100
		close(t.ready)
		t.logf("Tor подключён")
	}
}

// Status — состояние для интерфейса.
func (t *Tor) Status() (status string, progress int, errMsg string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status, t.progress, t.errMsg
}

func (t *Tor) Enabled() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status == "starting" || t.status == "ready"
}

// WaitReady ждёт подключения Tor не дольше d.
func (t *Tor) WaitReady(d time.Duration) bool {
	t.mu.Lock()
	ch, st := t.ready, t.status
	t.mu.Unlock()
	if st == "ready" {
		return true
	}
	if st != "starting" {
		return false
	}
	select {
	case <-ch:
		return true
	case <-time.After(d):
		return false
	}
}

var reBootstrap = regexp.MustCompile(`Bootstrapped (\d+)%`)

// Start запускает tor с указанным torrc.
func (t *Tor) Start(torExe, torrcPath, libDir, workDir, socks, pidFile string) error {
	t.Stop()
	killStaleTor(torExe, pidFile)
	cmd := exec.Command(torExe, "-f", torrcPath)
	cmd.Dir = workDir
	if runtime.GOOS == "linux" && libDir != "" {
		cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+libDir)
	}
	hideWindow(cmd)
	bindChild(cmd)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("не удалось запустить tor: %w", err)
	}
	afterStart(cmd)
	if pidFile != "" {
		_ = os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)
	}
	var tailMu sync.Mutex
	var tail []string
	t.mu.Lock()
	t.cmd, t.socks, t.external = cmd, socks, false
	t.status, t.progress, t.errMsg = "starting", 0, ""
	t.ready = make(chan struct{})
	t.mu.Unlock()
	t.logf("Tor запускается…")

	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			line := sc.Text()
			if m := reBootstrap.FindStringSubmatch(line); m != nil {
				p, _ := strconv.Atoi(m[1])
				t.mu.Lock()
				if t.cmd == cmd {
					t.progress = p
				}
				t.mu.Unlock()
				if p == 100 {
					t.setReady()
				}
			}
			if strings.Contains(line, "[warn]") || strings.Contains(line, "[err]") {
				t.logf("tor: %s", trimTorLog(line))
				tailMu.Lock()
				tail = append(tail, trimTorLog(line))
				if len(tail) > 30 {
					tail = tail[1:]
				}
				tailMu.Unlock()
			}
		}
	}()
	go func() {
		err := cmd.Wait()
		if pidFile != "" {
			_ = os.Remove(pidFile)
		}
		tailMu.Lock()
		reason := explainTorExit(tail, err)
		tailMu.Unlock()
		t.mu.Lock()
		if t.cmd == cmd {
			t.cmd = nil
			t.status = "error"
			t.errMsg = "Tor завершился: " + reason
			t.logf("%s", t.errMsg)
		}
		t.mu.Unlock()
	}()
	return nil
}

// explainTorExit переводит причину завершения tor на понятный язык.
func explainTorExit(tail []string, err error) string {
	all := strings.ToLower(strings.Join(tail, "\n"))
	switch {
	case strings.Contains(all, "another tor process is running"):
		return "работает старая копия tor — перезапустите программу или компьютер"
	case strings.Contains(all, "address already in use") || strings.Contains(all, "could not bind"):
		return "порт Tor занят другой программой"
	case strings.Contains(all, "managed proxy") || strings.Contains(all, "pluggable transport") ||
		strings.Contains(all, "clienttransportplugin"):
		return "не запустился транспорт мостов (lyrebird) — попробуйте другой тип мостов"
	}
	// «[err] Reading config failed--see warnings above» — показываем само предупреждение.
	for i := len(tail) - 1; i >= 0; i-- {
		l := tail[i]
		if strings.Contains(l, "see warnings above") || strings.Contains(strings.ToLower(l), "clock") {
			continue
		}
		if strings.Contains(l, "[warn]") || strings.Contains(l, "[err]") {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(l, "[warn]"), "[err]"))
		}
	}
	if len(tail) > 0 {
		return tail[len(tail)-1]
	}
	if err != nil {
		return err.Error()
	}
	return "без сообщения об ошибке"
}

func trimTorLog(l string) string {
	if i := strings.Index(l, "["); i >= 0 {
		return l[i:]
	}
	return l
}

func (t *Tor) Stop() {
	t.mu.Lock()
	cmd := t.cmd
	t.cmd = nil
	t.external = false
	if t.status != "off" {
		t.status, t.progress, t.errMsg = "off", 0, ""
	}
	t.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

// Dial открывает соединение через Tor; DNS разрешается на стороне Tor.
func (t *Tor) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	t.mu.Lock()
	socks, st := t.socks, t.status
	t.mu.Unlock()
	if st != "ready" && st != "starting" {
		return nil, errors.New("Tor выключен")
	}
	return socksDial(ctx, socks, host, port)
}

var socksErrors = map[byte]string{
	1: "ошибка Tor", 2: "запрещено", 3: "сеть недоступна", 4: "узел недоступен",
	5: "соединение отклонено", 6: "истекло время (TTL)", 7: "команда не поддерживается", 8: "тип адреса не поддерживается",
}

// socksDial — минимальный клиент SOCKS5 (CONNECT по имени домена).
func socksDial(ctx context.Context, proxy, host string, port int) (net.Conn, error) {
	c, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, fmt.Errorf("Tor SOCKS недоступен: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else {
		_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	}
	fail := func(e error) (net.Conn, error) { c.Close(); return nil, e }
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		return fail(err)
	}
	r := make([]byte, 2)
	if _, err := io.ReadFull(c, r); err != nil || r[0] != 5 || r[1] != 0 {
		return fail(errors.New("Tor SOCKS: ошибка рукопожатия"))
	}
	if len(host) > 255 {
		return fail(errors.New("слишком длинное имя"))
	}
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append(req, 1)
		req = append(req, ip.To4()...)
	} else if ip != nil {
		req = append(req, 4)
		req = append(req, ip.To16()...)
	} else {
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		return fail(err)
	}
	h := make([]byte, 4)
	if _, err := io.ReadFull(c, h); err != nil {
		return fail(fmt.Errorf("Tor не ответил: %w", err))
	}
	if h[1] != 0 {
		msg := socksErrors[h[1]]
		if msg == "" {
			msg = "код " + strconv.Itoa(int(h[1]))
		}
		return fail(errors.New("Tor: " + msg))
	}
	var skip int
	switch h[3] {
	case 1:
		skip = 4
	case 4:
		skip = 16
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return fail(err)
		}
		skip = int(l[0])
	}
	if _, err := io.ReadFull(c, make([]byte, skip+2)); err != nil {
		return fail(err)
	}
	_ = c.SetDeadline(time.Time{})
	return c, nil
}

// TorPaths — где лежит tor на ПК.
type TorPaths struct {
	Root, Exe, LibDir, PTConfig, GeoIPDir string
}

// FindTor ищет tor рядом с программой (папка tor/), затем в /opt/obhod/tor.
func FindTor() (*TorPaths, error) {
	var roots []string
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		roots = append(roots, filepath.Join(filepath.Dir(exe), "tor"))
	}
	roots = append(roots, "/opt/obhod/tor", "/usr/lib/obhod/tor")
	name := "tor"
	if runtime.GOOS == "windows" {
		name = "tor.exe"
	}
	for _, r := range roots {
		exe := filepath.Join(r, "tor", name)
		if !fileExists(exe) {
			continue
		}
		p := &TorPaths{Root: r, Exe: exe, LibDir: filepath.Join(r, "tor")}
		if c := filepath.Join(r, "pt", "pt_config.json"); fileExists(c) {
			p.PTConfig = c
		}
		if fileExists(filepath.Join(r, "data", "geoip")) {
			p.GeoIPDir = filepath.Join(r, "data")
		}
		return p, nil
	}
	// Системный tor (например, apt install tor) — без встроенных мостов.
	if p, err := exec.LookPath(name); err == nil {
		return &TorPaths{Root: filepath.Dir(p), Exe: p}, nil
	}
	return nil, errors.New("tor не найден рядом с программой")
}
