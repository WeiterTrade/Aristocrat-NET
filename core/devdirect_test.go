package main

import (
	"strings"
	"testing"
)

// Сборка для всех пользователей: маршрута «Ебаная Чукотка» нет, даже если код вшит;
// у Edward Version он есть.
func TestEditionGatesMoscowRoute(t *testing.T) {
	oldCode, oldEd := devDirectCode, edition
	defer func() { devDirectCode, edition = oldCode, oldEd }()
	devDirectCode = "d1:192.0.2.1:443:" + strings.Repeat("a", 64) + ":" + strings.Repeat("b", 32)
	edition = ""
	if !devBuild && (directAvailable() || NewDirectLink(t.TempDir(), t.Logf) != nil) {
		t.Fatal("в сборке для всех пользователей есть «Ебаная Чукотка»")
	}
	if !devBuild && strings.Contains(versionLabel(), "Edward") {
		t.Fatal("в сборке для всех пользователей написано Edward Version")
	}
	edition = "edward"
	if !directAvailable() || NewDirectLink(t.TempDir(), t.Logf) == nil {
		t.Fatal("в Edward Version нет «Ебаной Чукотки»")
	}
	if !strings.Contains(versionLabel(), "Edward Version") {
		t.Fatal("нет подписи Edward Version")
	}
}
