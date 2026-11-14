package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// Свои мосты: недоступные убираются, быстрые идут первыми, snowflake остаётся.
func TestRankBridges(t *testing.T) {
	fast, _ := net.Listen("tcp", "127.0.0.1:0")
	defer fast.Close()
	slowLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer slowLn.Close()
	dead := freePort(t)
	slowAddr := slowLn.Addr().String()

	custom := strings.Join([]string{
		"Bridge obfs4 " + slowAddr + " AAAA cert=x iat-mode=0",
		fmt.Sprintf("obfs4 127.0.0.1:%d BBBB cert=y iat-mode=0", dead),
		"webtunnel [2001:db8::1]:443 CCCC url=https://" + fast.Addr().String() + "/path ver=0.0.1",
		"snowflake 192.0.2.3:80 DDDD fingerprint=x url=https://snowflake-broker.example/",
		"# комментарий",
	}, "\n")
	out := rankBridges(custom, func(ctx context.Context, addr string) (net.Conn, error) {
		if addr == slowAddr {
			time.Sleep(150 * time.Millisecond) // «далёкий» мост
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}, t.Logf)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("ожидалось 3 моста (без недоступного):\n%s", out)
	}
	if !strings.HasPrefix(lines[0], "webtunnel") || !strings.Contains(lines[1], slowAddr) || !strings.HasPrefix(lines[2], "snowflake") {
		t.Fatalf("неверный порядок:\n%s", out)
	}
	// Если не ответил ни один — возвращаем всё как было.
	all := fmt.Sprintf("obfs4 127.0.0.1:%d X cert=z iat-mode=0", dead)
	if got := rankBridges(all, nil, t.Logf); got != all {
		t.Fatalf("при полной недоступности список не должен меняться: %q", got)
	}
}
