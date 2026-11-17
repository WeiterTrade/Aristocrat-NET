// devhash — хэш пароля режима разработчика для сборки (CI): читает DEV_PASSWORD, печатает PBKDF2.
// Сам пароль в программу не попадает — только этот хэш (тот же алгоритм, что в devserver.go).
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func main() {
	p := strings.Join(strings.Fields(os.Getenv("DEV_PASSWORD")), "")
	if p == "" {
		return // секрета нет — сборка разработчика без пароля не откроет режим
	}
	mac := hmac.New(sha256.New, []byte(p))
	mac.Write([]byte("AristocratNET-dev-v1"))
	mac.Write([]byte{0, 0, 0, 1})
	u := mac.Sum(nil)
	out := append([]byte(nil), u...)
	for i := 1; i < 600000; i++ {
		mac.Reset()
		mac.Write(u)
		u = mac.Sum(u[:0])
		for j := range out {
			out[j] ^= u[j]
		}
	}
	fmt.Print(hex.EncodeToString(out))
}
