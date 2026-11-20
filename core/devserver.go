//go:build dev

package main

// Сборка разработчика: раздача интернета («Ебаная Чукотка») и журнал подключений.
// В пользовательских сборках этого файла нет (см. devserver_stub.go).
//
// Как устроено: компьютер с белым IP открывает порт (443, если занят — 8443) с TLS
// (самоподписанный сертификат, его отпечаток вшит в приложения пользователей) и принимает
// SOCKS5 с логином: ключ доступа + номер установки, в пароле — сведения для журнала.
// За ним — тот же обход, что работает на этом компьютере («Авто»).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
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
	clients map[string]*devClient
	journal []string

	direct     *Engine    // раздача (белый IP, TLS на внешнем порту)
	exits      exitPool   // сервер: соединения от компьютера-выхода
	agent      *exitAgent // этот компьютер — выход для сервера
	directPort int
	directErr  string
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

// shareEngine — прокси раздачи с тем же обходом, что на этом компьютере («Авто»: обход DPI,
// при блокировке — WARP или Tor; правила для российских сайтов, реклама), вход — по логину.
func (d *DevServer) shareEngine(auth *ShareAuth) *Engine {
	a := d.a
	eng := NewEngine(a.res, func(string, ...any) {})
	route := a.settings().Route
	if route != RouteWarp && route != RouteTor { // раздача — всегда с полным обходом («Авто»)
		route = RouteAuto
	}
	eng.Route.Store(route)
	eng.Mode.Store(a.settings().Mode)
	eng.Tor, eng.Warp, eng.Local = a.eng.Tor, a.eng.Warp, a.eng.Local
	eng.Ads = a.ads
	eng.BlockQUIC = true
	eng.Share = auth
	return eng
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
	V     int    `json:"v"`
	Cert  string `json:"cert"`  // сертификат TLS (PEM)
	Key   string `json:"key"`   // его закрытый ключ (PEM)
	Token string `json:"token"` // ключ доступа приложений
}

const devKeyPrefix = "ARISTONET-KEY2:"

// ExportKey — ключ сервера одной строкой (резервная копия: сертификат и ключ доступа).
// После переустановки восстановите его — код подключения останется прежним, пересобирать приложения не придётся.
func (d *DevServer) ExportKey() (string, error) {
	if _, _, _, err := d.directIdentity(); err != nil {
		return "", err
	}
	crt, err1 := os.ReadFile(d.path("dev-direct.crt"))
	key, err2 := os.ReadFile(d.path("dev-direct.key"))
	tok, err3 := os.ReadFile(d.path("dev-direct.token"))
	if err1 != nil || err2 != nil || err3 != nil {
		return "", errors.New("ключа ещё нет: включите раздачу хотя бы один раз")
	}
	j, _ := json.Marshal(devKeyFile{V: 2, Cert: string(crt), Key: string(key), Token: strings.TrimSpace(string(tok))})
	return devKeyPrefix + base64.RawURLEncoding.EncodeToString(j), nil
}

// ImportKey восстанавливает ключ сервера.
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
	if json.Unmarshal(j, &k) != nil || len(k.Token) != 32 {
		return errors.New("ключ повреждён")
	}
	if _, err := tls.X509KeyPair([]byte(k.Cert), []byte(k.Key)); err != nil {
		return errors.New("ключ повреждён")
	}
	was := d.On()
	if was {
		d.Stop()
	}
	for name, data := range map[string]string{"dev-direct.crt": k.Cert, "dev-direct.key": k.Key, "dev-direct.token": k.Token} {
		if err := os.WriteFile(d.path(name), []byte(data), 0o600); err != nil {
			return err
		}
	}
	d.a.logf("Ключ сервера восстановлен")
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
	if a.dev != nil {
		a.dev.Stop()
		a.dev.StopExit()
	}
	a.mu.Lock()
	a.s.DevMode, a.s.DevDirect, a.s.DevExit = false, false, false
	a.mu.Unlock()
	a.save()
}

// devSetShare включает или выключает раздачу (и запоминает выбор).
func (a *App) devSetShare(on bool) error {
	if a.dev == nil || !a.settings().DevMode {
		return errors.New("режим разработчика выключен")
	}
	a.mu.Lock()
	a.s.DevDirect = on
	a.mu.Unlock()
	a.save()
	if on {
		return a.dev.Start()
	}
	a.dev.Stop()
	return nil
}

// devSetExit включает или выключает выход в интернет через этот компьютер.
func (a *App) devSetExit(on bool) error {
	if a.dev == nil || !a.settings().DevMode {
		return errors.New("режим разработчика выключен")
	}
	a.mu.Lock()
	a.s.DevExit = on
	a.mu.Unlock()
	a.save()
	if on {
		return a.dev.StartExit()
	}
	a.dev.StopExit()
	return nil
}

func (a *App) devInit() {
	a.dev = newDevServer(a)
	st := a.settings()
	if st.DevMode && st.DevDirect {
		go func() {
			if err := a.dev.Start(); err != nil {
				a.logf("Раздача: %v", err)
			}
		}()
	}
	if st.DevMode && st.DevExit {
		go func() {
			if err := a.dev.StartExit(); err != nil {
				a.logf("Выход: %v", err)
			}
		}()
	}
}

func (a *App) devStop() {
	if a.dev != nil {
		a.dev.Stop()
		a.dev.StopExit()
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
		m["exit"] = a.dev.ExitOn()
		m["exit_status"] = a.dev.ExitStatus()
	}
	return m
}

// ---------------------------------------------------------------------------
// Раздача: компьютер с белым IP принимает TLS на внешнем порту.

// directIdentity — сертификат TLS (самоподписанный, отпечаток — в коде подключения) и ключ доступа.
func (d *DevServer) directIdentity() (tls.Certificate, string, string, error) {
	crt, key, tokPath := d.path("dev-direct.crt"), d.path("dev-direct.key"), d.path("dev-direct.token")
	cert, err := tls.LoadX509KeyPair(crt, key)
	if err != nil {
		pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return tls.Certificate{}, "", "", err
		}
		sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
		tpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: "www.microsoft.com"},
			NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().AddDate(20, 0, 0),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames: []string{"www.microsoft.com"}}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &pk.PublicKey, pk)
		if err != nil {
			return tls.Certificate{}, "", "", err
		}
		kb, _ := x509.MarshalECPrivateKey(pk)
		_ = os.WriteFile(crt, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
		_ = os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
		if cert, err = tls.LoadX509KeyPair(crt, key); err != nil {
			return tls.Certificate{}, "", "", err
		}
	}
	sum := sha256.Sum256(cert.Certificate[0])
	tok := ""
	if b, err := os.ReadFile(tokPath); err == nil && len(strings.TrimSpace(string(b))) == 32 {
		tok = strings.TrimSpace(string(b))
	} else {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		tok = hex.EncodeToString(b)
		_ = os.WriteFile(tokPath, []byte(tok), 0o600)
	}
	return cert, hex.EncodeToString(sum[:]), tok, nil
}

func (d *DevServer) On() bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.direct != nil
}

// Start открывает порт раздачи (443; если занят — 8443).
func (d *DevServer) Start() error {
	if d.On() {
		return nil
	}
	cert, _, tok, err := d.directIdentity()
	if err != nil {
		return fmt.Errorf("не удалось создать сертификат: %w", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}}
	var ln net.Listener
	port := d.a.settings().DevDirectPort
	ports := []int{port}
	if port == 0 {
		ports = []int{443, 8443}
	}
	var lerr error
	for _, p := range ports {
		if ln, lerr = tls.Listen("tcp", ":"+strconv.Itoa(p), cfg); lerr == nil {
			port = p
			break
		}
	}
	if ln == nil {
		d.mu.Lock()
		d.directErr = "порт занят: " + lerr.Error()
		d.mu.Unlock()
		return fmt.Errorf("не удалось открыть порт раздачи: %w", lerr)
	}
	allowFirewall(port)
	eng := d.shareEngine(&ShareAuth{Check: func(user, pass string) *ShareClient {
		if user == exitUserPrefix+tok {
			if sec := exitSecret(); sec != "" && hmac.Equal([]byte(pass), []byte(sec)) {
				return &ShareClient{Exit: true}
			}
			return nil
		}
		if len(user) != 48 || !hmac.Equal([]byte(user[:32]), []byte(tok)) {
			return nil
		}
		return d.check(user[32:], pass)
	}, OnExit: d.holdExit, Exit: d.dialExit})
	a := d.a
	a.sharing.Store(true)
	go a.startUpstreams(false)
	eng.Serve(ln)
	d.mu.Lock()
	d.direct, d.directPort, d.directErr = eng, port, ""
	d.mu.Unlock()
	d.a.logf("Раздача включена: порт %d", port)
	return nil
}

func (d *DevServer) Stop() {
	d.mu.Lock()
	eng := d.direct
	d.direct = nil
	d.mu.Unlock()
	if eng != nil {
		eng.Stop()
		d.a.updSharing()
		d.a.logf("Раздача выключена")
	}
}

// Status — строка состояния.
func (d *DevServer) Status() string {
	d.mu.Lock()
	on, port, derr := d.direct != nil, d.directPort, d.directErr
	active := 0
	for _, c := range d.clients {
		if c.stats.Active.Load() > 0 {
			active++
		}
	}
	d.mu.Unlock()
	if !on {
		if derr != "" {
			return "Выключена (" + derr + ")"
		}
		return "Выключена"
	}
	return fmt.Sprintf("Работает: порт %d, подключено: %d · %s", port, active, d.exitServerStatus())
}

// Code — код для секрета GitHub DEV_DIRECT.
func (d *DevServer) Code() (string, error) {
	d.mu.Lock()
	port := d.directPort
	d.mu.Unlock()
	if !d.On() {
		return "", errors.New("сначала включите раздачу")
	}
	ip, _, err := publicIP()
	if err != nil || net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil {
		return "", errors.New("не удалось узнать внешний IP-адрес этого компьютера")
	}
	_, fp, tok, err := d.directIdentity()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("d1:%s:%d:%s:%s", ip, port, fp, tok), nil
}
