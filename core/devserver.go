//go:build dev

package main

// Сборка разработчика: раздача интернета через Tor (скрытый сервис) и журнал подключений.
// В пользовательских сборках этого файла нет (см. devserver_stub.go).
//
// Как устроено:
//   • отдельный tor раздачи публикует скрытый сервис (адрес .onion) с авторизацией клиентов:
//     подключиться могут только приложения с вшитым ключом доступа;
//   • сначала «открытый» режим (single onion: со стороны разработчика путь в одно звено — быстрее);
//     если tor так не подключился за 2 минуты (Tor в сети заблокирован) — обычный режим с мостами;
//   • за адресом — отдельный прокси (обход DPI, блокировка рекламы), вход по логину SOCKS5:
//     номер установки и сведения о пользователе — для журнала.

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const devBuild = true

// devPassHash — PBKDF2 пароля режима разработчика (задаётся при сборке из секрета DEV_PASSWORD).
var devPassHash = ""

const devPassSalt = "AristocratNET-dev-v1"
const devPassIter = 600000

// pbkdf2SHA256 — PBKDF2-HMAC-SHA256, один блок (32 байта).
func pbkdf2SHA256(pass, salt []byte, iter int) []byte {
	mac := hmac.New(sha256.New, pass)
	mac.Write(salt)
	mac.Write([]byte{0, 0, 0, 1})
	u := mac.Sum(nil)
	out := append([]byte(nil), u...)
	for i := 1; i < iter; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(u[:0])
		for j := range out {
			out[j] ^= u[j]
		}
	}
	return out
}

func normalizeDevPass(p string) string { return strings.Join(strings.Fields(p), "") }

func checkDevPassword(p string) error {
	if devPassHash == "" {
		return errors.New("пароль не задан при сборке: добавьте секрет DEV_PASSWORD в репозиторий GitHub и пересоберите")
	}
	h := pbkdf2SHA256([]byte(normalizeDevPass(p)), []byte(devPassSalt), devPassIter)
	want, _ := hex.DecodeString(devPassHash)
	if !hmac.Equal(h, want) {
		return errors.New("неверный пароль")
	}
	return nil
}

// ---------------------------------------------------------------------------

type devClient struct {
	ID, Name, IP, Country, City, Version string
	First, Last                          time.Time
	stats                                *ShareClient
}

type DevServer struct {
	a *App

	mu      sync.Mutex
	on      bool
	tor     *Tor
	eng     *Engine
	mode    string // "single" — открытый режим, "bridges" — с мостами
	onion   string
	clients map[string]*devClient
	journal []string
	gen     int // поколение запуска (чтобы старый сторож не перезапускал новый tor)
}

func newDevServer(a *App) *DevServer {
	d := &DevServer{a: a, clients: map[string]*devClient{}}
	if b, err := os.ReadFile(d.path("dev-journal.txt")); err == nil {
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		if len(lines) > 300 {
			lines = lines[len(lines)-300:]
		}
		d.journal = lines
	}
	return d
}

func (d *DevServer) path(p ...string) string {
	return filepath.Join(append([]string{d.a.dir}, p...)...)
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// ensureClientKey — ключ доступа приложений (x25519): закрытый — в код подключения, открытый — tor раздачи.
func (d *DevServer) ensureClientKey() (priv, pub string, err error) {
	if b, err := os.ReadFile(d.path("dev-client.key")); err == nil {
		if raw, err := b32.DecodeString(strings.TrimSpace(string(b))); err == nil && len(raw) == 32 {
			k, err := ecdh.X25519().NewPrivateKey(raw)
			if err == nil {
				return b32.EncodeToString(raw), b32.EncodeToString(k.PublicKey().Bytes()), nil
			}
		}
	}
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	priv, pub = b32.EncodeToString(k.Bytes()), b32.EncodeToString(k.PublicKey().Bytes())
	return priv, pub, os.WriteFile(d.path("dev-client.key"), []byte(priv), 0o600)
}

func (d *DevServer) prepareHS() error {
	_, pub, err := d.ensureClientKey()
	if err != nil {
		return err
	}
	ac := d.path("dev-hs", "authorized_clients")
	if err := os.MkdirAll(ac, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(d.path("dev-hs"), 0o700) // tor требует закрытую папку (Linux)
	return os.WriteFile(filepath.Join(ac, "app.auth"), []byte("descriptor:x25519:"+pub+"\n"), 0o600)
}

func (d *DevServer) On() bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.on
}

// Start включает раздачу.
func (d *DevServer) Start() error {
	d.mu.Lock()
	if d.on {
		d.mu.Unlock()
		return nil
	}
	d.on = true
	d.gen++
	gen := d.gen
	d.mu.Unlock()
	if err := d.prepareHS(); err != nil {
		d.Stop()
		return fmt.Errorf("не удалось подготовить ключи: %w", err)
	}
	// Прокси раздачи: обход DPI и блокировка рекламы, вход только по логину.
	eng := NewEngine(d.a.res, func(string, ...any) {})
	eng.Route.Store(RouteDPI)
	eng.Ads = d.a.ads
	eng.BlockQUIC = true
	eng.Share = &ShareAuth{Check: d.check}
	port := 0
	if l, err := net.Listen("tcp", "127.0.0.1:0"); err == nil {
		port = l.Addr().(*net.TCPAddr).Port
		l.Close()
	}
	if err := eng.Start(port); err != nil {
		d.Stop()
		return err
	}
	d.mu.Lock()
	d.eng = eng
	d.mu.Unlock()
	d.a.logf("Раздача: запускаю…")
	go d.run(gen, port)
	return nil
}

func (d *DevServer) run(gen, port int) {
	mode := "single"
	for {
		d.mu.Lock()
		if !d.on || d.gen != gen {
			d.mu.Unlock()
			return
		}
		d.mode = mode
		d.mu.Unlock()
		t, err := d.startTor(mode, port)
		if err != nil {
			d.a.logf("Раздача: %v", err)
			time.Sleep(30 * time.Second)
			continue
		}
		d.mu.Lock()
		d.tor = t
		d.mu.Unlock()
		if t.WaitReady(2 * time.Minute) {
			if b, err := os.ReadFile(d.path("dev-hs", "hostname")); err == nil {
				d.mu.Lock()
				d.onion = strings.TrimSpace(string(b))
				d.mu.Unlock()
			}
			if mode == "single" {
				d.a.logf("Раздача включена (быстрый режим): %s", d.Onion())
			} else {
				d.a.logf("Раздача включена (через мосты Tor): %s", d.Onion())
			}
			// Сторож: если tor упал — перезапустить.
			for {
				time.Sleep(10 * time.Second)
				d.mu.Lock()
				alive := d.on && d.gen == gen
				d.mu.Unlock()
				if !alive {
					return
				}
				if !t.Enabled() {
					d.a.logf("Раздача: tor остановился — перезапускаю")
					break
				}
			}
			continue
		}
		t.Stop()
		if mode == "single" {
			d.a.logf("Раздача: Tor напрямую не подключился — пробую через мосты")
			mode = "bridges"
		} else {
			d.a.logf("Раздача: Tor не подключился и через мосты — повторю через минуту")
			mode = "single"
			time.Sleep(time.Minute)
		}
	}
}

func (d *DevServer) startTor(mode string, port int) (*Tor, error) {
	paths, err := FindTor()
	if err != nil {
		return nil, err
	}
	_ = os.MkdirAll(d.path("dev-tor-data"), 0o700)
	hs := fmt.Sprintf("HiddenServiceDir dev-hs\nHiddenServicePort 443 127.0.0.1:%d\n", port)
	var torrc string
	if mode == "single" {
		torrc = "SOCKSPort 0\nDataDirectory dev-tor-data\nLog notice stdout\nAvoidDiskWrites 1\n" + hs +
			"HiddenServiceSingleHopMode 1\nHiddenServiceNonAnonymousMode 1\n"
	} else {
		st := d.a.settings()
		ptDir := ""
		if paths.PTConfig != "" {
			if err := syncDir(filepath.Dir(paths.PTConfig), d.path("pt")); err == nil {
				ptDir = "pt"
			}
		}
		bridges := st.Bridges
		if bridges == "none" {
			bridges = "auto"
		}
		torrc, err = BuildTorrc(TorOptions{Bridges: bridges, Custom: st.CustomBridges, SocksAddr: "0", DataDir: "dev-tor-data",
			PTConfigPath: paths.PTConfig, PTDir: ptDir, WorkDir: d.a.dir})
		if err != nil {
			return nil, err
		}
		torrc += hs
	}
	if err := os.WriteFile(d.path("dev-torrc"), []byte(torrc), 0o600); err != nil {
		return nil, err
	}
	t := NewTor(func(f string, args ...any) { d.a.logf("Раздача: "+f, args...) })
	if err := t.Start(paths.Exe, "dev-torrc", paths.LibDir, d.a.dir, "", d.path("dev-tor.pid")); err != nil {
		return nil, err
	}
	return t, nil
}

// Stop выключает раздачу.
func (d *DevServer) Stop() {
	d.mu.Lock()
	d.on = false
	d.gen++
	t, eng := d.tor, d.eng
	d.tor, d.eng = nil, nil
	d.mu.Unlock()
	if t != nil {
		t.Stop()
	}
	if eng != nil {
		eng.Stop()
	}
	d.a.logf("Раздача выключена")
}

func (d *DevServer) Onion() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.onion
}

// Status — строка состояния для интерфейса.
func (d *DevServer) Status() string {
	d.mu.Lock()
	on, t, mode := d.on, d.tor, d.mode
	active := 0
	for _, c := range d.clients {
		if c.stats.Active.Load() > 0 {
			active++
		}
	}
	d.mu.Unlock()
	if !on {
		return "Выключена"
	}
	if t == nil || !t.WaitReady(0) {
		p := 0
		if t != nil {
			_, p, _ = t.Status()
		}
		return fmt.Sprintf("Запускается… %d%%", p)
	}
	m := "быстрый режим"
	if mode == "bridges" {
		m = "через мосты"
	}
	return fmt.Sprintf("Работает (%s), подключено: %d", m, active)
}

// check — вход пользователя в прокси раздачи (логин SOCKS5).
func (d *DevServer) check(user, pass string) *ShareClient {
	if len(user) != 16 {
		return nil
	}
	if _, err := hex.DecodeString(user); err != nil {
		return nil
	}
	f := strings.Split(pass, "|")
	for len(f) < 6 {
		f = append(f, "")
	}
	now := time.Now()
	d.mu.Lock()
	c := d.clients[user]
	isNew := c == nil
	if isNew {
		c = &devClient{ID: user, First: now, stats: &ShareClient{}}
		d.clients[user] = c
	}
	gap := now.Sub(c.Last)
	c.Name, c.IP, c.Country, c.City, c.Version, c.Last = f[1], f[2], f[3], f[4], f[5], now
	d.mu.Unlock()
	if isNew || gap > 15*time.Minute {
		d.addJournal(fmt.Sprintf("%s подключился: %s", now.Format("02.01 15:04"), describeClient(c)))
	}
	return c.stats
}

func describeClient(c *devClient) string {
	place := strings.Trim(strings.Join([]string{c.City, countryName(c.Country)}, ", "), ", ")
	parts := []string{nz(c.Name, "без имени")}
	if place != "" {
		parts = append(parts, place)
	}
	if c.IP != "" {
		parts = append(parts, "IP "+c.IP)
	}
	if c.Version != "" {
		parts = append(parts, "v"+c.Version)
	}
	return strings.Join(parts, " · ")
}

func nz(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

var countryNames = map[string]string{"RU": "Россия", "KZ": "Казахстан", "BY": "Беларусь", "UA": "Украина", "UZ": "Узбекистан",
	"KG": "Киргизия", "AM": "Армения", "GE": "Грузия", "AZ": "Азербайджан", "TJ": "Таджикистан", "DE": "Германия", "TR": "Турция"}

func countryName(cc string) string {
	if n := countryNames[strings.ToUpper(cc)]; n != "" {
		return n
	}
	return cc
}

func (d *DevServer) addJournal(line string) {
	d.mu.Lock()
	d.journal = append(d.journal, line)
	if len(d.journal) > 300 {
		d.journal = d.journal[len(d.journal)-300:]
	}
	d.mu.Unlock()
	if f, err := os.OpenFile(d.path("dev-journal.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
		_, _ = f.WriteString(line + "\n")
		f.Close()
	}
}

// JournalText — журнал подключений: сначала кто подключался (сводка), затем события.
func (d *DevServer) JournalText() string {
	d.mu.Lock()
	cl := make([]*devClient, 0, len(d.clients))
	for _, c := range d.clients {
		cl = append(cl, c)
	}
	events := append([]string(nil), d.journal...)
	d.mu.Unlock()
	sort.Slice(cl, func(i, j int) bool { return cl[i].Last.After(cl[j].Last) })
	nl := "\n"
	if runtime.GOOS == "windows" {
		nl = "\r\n"
	}
	var b strings.Builder
	b.WriteString("Пользователи (с момента запуска программы):" + nl)
	if len(cl) == 0 {
		b.WriteString("  пока никто не подключался" + nl)
	}
	for _, c := range cl {
		state := "был в " + c.Last.Format("15:04")
		if n := c.stats.Active.Load(); n > 0 {
			state = fmt.Sprintf("сейчас подключён (%d соед.)", n)
		}
		fmt.Fprintf(&b, "  %s — %s; трафик: ↓ %s, ↑ %s%s", describeClient(c), state,
			humanBytes(c.stats.Down.Load()), humanBytes(c.stats.Up.Load()), nl)
	}
	b.WriteString(nl + "События:" + nl)
	for i := len(events) - 1; i >= 0; i-- {
		b.WriteString("  " + events[i] + nl)
	}
	return b.String()
}

func (d *DevServer) ClearJournal() {
	d.mu.Lock()
	d.journal = nil
	d.mu.Unlock()
	_ = os.Remove(d.path("dev-journal.txt"))
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f ГБ", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f МБ", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f КБ", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d Б", n)
}

// ---------------------------------------------------------------------------
// Ключ сервера и код подключения

type devKeyFile struct {
	V          int    `json:"v"`
	Secret     string `json:"secret"` // hs_ed25519_secret_key (base64)
	Public     string `json:"public"` // hs_ed25519_public_key (base64)
	Hostname   string `json:"hostname"`
	ClientPriv string `json:"client_priv"`
}

const devKeyPrefix = "ARISTONET-KEY1:"

// Code — код подключения для пользовательских сборок (файл dev-code.txt в репозитории).
func (d *DevServer) Code() (string, error) {
	host := d.Onion()
	if host == "" {
		if b, err := os.ReadFile(d.path("dev-hs", "hostname")); err == nil {
			host = strings.TrimSpace(string(b))
		}
	}
	if host == "" {
		return "", errors.New("сначала включите раздачу: адрес появится через минуту-две")
	}
	priv, _, err := d.ensureClientKey()
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(host, ".onion") + ":" + priv, nil
}

// ExportKey — ключ сервера одной строкой (для резервной копии).
func (d *DevServer) ExportKey() (string, error) {
	sec, err1 := os.ReadFile(d.path("dev-hs", "hs_ed25519_secret_key"))
	pub, err2 := os.ReadFile(d.path("dev-hs", "hs_ed25519_public_key"))
	host, _ := os.ReadFile(d.path("dev-hs", "hostname"))
	if err1 != nil || err2 != nil {
		return "", errors.New("ключа ещё нет: включите раздачу хотя бы один раз")
	}
	priv, _, err := d.ensureClientKey()
	if err != nil {
		return "", err
	}
	j, _ := json.Marshal(devKeyFile{V: 1, Secret: base64.StdEncoding.EncodeToString(sec), Public: base64.StdEncoding.EncodeToString(pub),
		Hostname: strings.TrimSpace(string(host)), ClientPriv: priv})
	return devKeyPrefix + base64.RawURLEncoding.EncodeToString(j), nil
}

// ImportKey восстанавливает ключ сервера (адрес останется прежним — пересобирать приложения не нужно).
func (d *DevServer) ImportKey(text string) error {
	text = strings.TrimSpace(text)
	i := strings.Index(text, devKeyPrefix)
	if i < 0 {
		return errors.New("это не ключ Aristocrat NET (строка должна начинаться с " + devKeyPrefix + ")")
	}
	raw := strings.Fields(text[i+len(devKeyPrefix):])
	if len(raw) == 0 {
		return errors.New("ключ пустой")
	}
	j, err := base64.RawURLEncoding.DecodeString(raw[0])
	if err != nil {
		return errors.New("ключ повреждён")
	}
	var k devKeyFile
	if json.Unmarshal(j, &k) != nil || k.Secret == "" || k.ClientPriv == "" {
		return errors.New("ключ повреждён")
	}
	sec, err1 := base64.StdEncoding.DecodeString(k.Secret)
	pub, err2 := base64.StdEncoding.DecodeString(k.Public)
	cp, err3 := b32.DecodeString(k.ClientPriv)
	if err1 != nil || err2 != nil || err3 != nil || len(cp) != 32 {
		return errors.New("ключ повреждён")
	}
	was := d.On()
	if was {
		d.Stop()
	}
	if err := os.MkdirAll(d.path("dev-hs"), 0o700); err != nil {
		return err
	}
	for name, data := range map[string][]byte{"hs_ed25519_secret_key": sec, "hs_ed25519_public_key": pub, "hostname": []byte(k.Hostname + "\n")} {
		if err := os.WriteFile(d.path("dev-hs", name), data, 0o600); err != nil {
			return err
		}
	}
	if err := os.WriteFile(d.path("dev-client.key"), []byte(k.ClientPriv), 0o600); err != nil {
		return err
	}
	d.mu.Lock()
	d.onion = k.Hostname
	d.mu.Unlock()
	d.a.logf("Ключ разработчика восстановлен: %s", k.Hostname)
	if was {
		return d.Start()
	}
	return nil
}

// SaveKey сохраняет ключ в файл.
func (d *DevServer) SaveKey(path string) error {
	k, err := d.ExportKey()
	if err != nil {
		return err
	}
	note := "Ключ сервера Aristocrat NET (раздача через разработчика).\n" +
		"Храните в надёжном месте и никому не передавайте. Восстановление: Настройки → Режим разработчика → Восстановить из файла.\n\n"
	return os.WriteFile(path, []byte(note+k+"\n"), 0o600)
}

// CloudDirs — папки облачных дисков на этом компьютере (Яндекс Диск, OneDrive, Google Диск, Dropbox).
func CloudDirs() []string {
	home, _ := os.UserHomeDir()
	cands := []string{os.Getenv("OneDrive"), os.Getenv("OneDriveConsumer")}
	for _, n := range []string{"YandexDisk", "Yandex.Disk", "Яндекс.Диск", "OneDrive", "Google Drive", "GoogleDrive", "Dropbox"} {
		cands = append(cands, filepath.Join(home, n))
	}
	if runtime.GOOS == "windows" {
		for _, drv := range []string{"G:", "H:"} {
			cands = append(cands, drv+`\My Drive`, drv+`\Мой диск`)
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, c := range cands {
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			out = append(out, c)
		}
	}
	return out
}

// SaveKeyToCloud — копии ключа во все найденные облачные папки.
func (d *DevServer) SaveKeyToCloud() ([]string, error) {
	dirs := CloudDirs()
	if len(dirs) == 0 {
		return nil, errors.New("облачные папки не найдены (Яндекс Диск, OneDrive, Google Диск, Dropbox). Сохраните ключ в файл и положите его в облако вручную")
	}
	var saved []string
	for _, dir := range dirs {
		p := filepath.Join(dir, "AristocratNET-ключ-разработчика.txt")
		if err := d.SaveKey(p); err == nil {
			saved = append(saved, p)
		}
	}
	if len(saved) == 0 {
		return nil, errors.New("не удалось записать ключ в облачные папки")
	}
	return saved, nil
}

// ---------------------------------------------------------------------------
// Приложение

// devUnlock — включить режим разработчика (по паролю).
func (a *App) devUnlock(pass string) error {
	if err := checkDevPassword(pass); err != nil {
		return err
	}
	a.mu.Lock()
	a.s.DevMode = true
	a.mu.Unlock()
	a.save()
	a.logf("Режим разработчика включён")
	return nil
}

func (a *App) devLock() {
	if a.dev != nil && a.dev.On() {
		a.dev.Stop()
	}
	a.mu.Lock()
	a.s.DevMode, a.s.DevShare = false, false
	a.mu.Unlock()
	a.save()
}

// devSetShare включает или выключает раздачу (и запоминает выбор).
func (a *App) devSetShare(on bool) error {
	if a.dev == nil || !a.settings().DevMode {
		return errors.New("режим разработчика выключен")
	}
	a.mu.Lock()
	a.s.DevShare = on
	a.mu.Unlock()
	a.save()
	if on {
		return a.dev.Start()
	}
	a.dev.Stop()
	return nil
}

func (a *App) devInit() {
	a.dev = newDevServer(a)
	st := a.settings()
	if st.DevMode && st.DevShare {
		go func() {
			if err := a.dev.Start(); err != nil {
				a.logf("Раздача: %v", err)
			}
		}()
	}
}

func (a *App) devStop() {
	if a.dev != nil && a.dev.On() {
		a.dev.Stop()
	}
}

// devState — для веб-интерфейса.
func (a *App) devState() map[string]any {
	st := a.settings()
	m := map[string]any{"build": true, "mode": st.DevMode}
	if st.DevMode && a.dev != nil {
		code, _ := a.dev.Code()
		m["share"] = a.dev.On()
		m["status"] = a.dev.Status()
		m["code"] = code
		m["clouds"] = CloudDirs()
	}
	return m
}
