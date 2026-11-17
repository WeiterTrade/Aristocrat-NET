//go:build dev

package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDevPassword(t *testing.T) {
	// RFC 7914 (PBKDF2-HMAC-SHA256, 1 итерация, первые 32 байта): "passwd"/"salt".
	got := hex.EncodeToString(pbkdf2SHA256([]byte("passwd"), []byte("salt"), 1))
	if got != "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc" {
		t.Fatalf("pbkdf2: %s", got)
	}
	old := devPassHash
	defer func() { devPassHash = old }()
	devPassHash = hex.EncodeToString(pbkdf2SHA256([]byte("testpass123"), []byte(devPassSalt), devPassIter))
	if err := checkDevPassword(" test pass 123 "); err != nil {
		t.Fatalf("верный пароль с пробелами: %v", err)
	}
	if checkDevPassword("wrong") == nil {
		t.Fatal("неверный пароль принят")
	}
}

func TestDevKeyRoundTrip(t *testing.T) {
	a := &App{dir: t.TempDir()}
	d := newDevServer(a)
	if err := d.prepareHS(); err != nil {
		t.Fatal(err)
	}
	// как будто tor уже создал ключи сервиса
	host := strings.Repeat("q", 56) + ".onion"
	os.WriteFile(filepath.Join(a.dir, "dev-hs", "hs_ed25519_secret_key"), []byte("SECRET"), 0o600)
	os.WriteFile(filepath.Join(a.dir, "dev-hs", "hs_ed25519_public_key"), []byte("PUBLIC"), 0o600)
	os.WriteFile(filepath.Join(a.dir, "dev-hs", "hostname"), []byte(host+"\n"), 0o600)
	code, err := d.Code()
	if err != nil || !strings.HasPrefix(code, strings.TrimSuffix(host, ".onion")+":") {
		t.Fatalf("код: %q %v", code, err)
	}
	old := devCode
	devCode = code
	ok := devAvailable()
	devCode = old
	if !ok {
		t.Fatalf("код не подходит для сборки: %q", code)
	}
	key, err := d.ExportKey()
	if err != nil {
		t.Fatal(err)
	}
	// восстановление на «другом компьютере»
	b := &App{dir: t.TempDir()}
	d2 := newDevServer(b)
	if err := d2.ImportKey("мусор\n" + key + "\n"); err != nil {
		t.Fatal(err)
	}
	if code2, _ := d2.Code(); code2 != code {
		t.Fatalf("после восстановления другой код: %q != %q", code2, code)
	}
	if sec, _ := os.ReadFile(filepath.Join(b.dir, "dev-hs", "hs_ed25519_secret_key")); string(sec) != "SECRET" {
		t.Fatal("ключ сервиса не восстановлен")
	}
	if d2.ImportKey("не ключ") == nil {
		t.Fatal("мусор принят как ключ")
	}
	// журнал
	if d.check("0123456789abcdef", devInfo("Ноутбук", "5.6.7.8", "RU", "Казань")) == nil {
		t.Fatal("клиент не пущен")
	}
	if d.check("bad", "") != nil {
		t.Fatal("неверный логин пущен")
	}
	if j := d.JournalText(); !strings.Contains(j, "Ноутбук · Казань, Россия · IP 5.6.7.8") {
		t.Fatalf("журнал: %s", j)
	}
}
