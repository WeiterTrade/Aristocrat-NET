package main

import "testing"

func TestAdBlock(t *testing.T) {
	a := NewAdBlock(t.TempDir(), nil)
	a.merge([]byte("! comment\n||ads.example.com^\n||cond.example^$client=1\n@@||ok.ads.example.com^\n0.0.0.0 tracker.example.net\nplain.example.org\n"))
	cases := map[string]bool{
		"doubleclick.net": true, "googleads.g.doubleclick.net": true, "adservice.google.com": true,
		"ads.example.com": true, "x.ads.example.com": true, "ok.ads.example.com": false,
		"tracker.example.net": true, "plain.example.org": true, "cond.example": false,
		"www.youtube.com": false, "rr3---sn-abc.googlevideo.com": false, "google.com": false,
		"img.1xbet-mirror.com": true, "example.com": false, "1.2.3.4": false, "t.me": false,
	}
	for h, want := range cases {
		if got := a.Blocked(h); got != want {
			t.Errorf("%s: %v, ожидалось %v", h, got, want)
		}
	}
	a.Enabled = func() bool { return false }
	if a.Blocked("doubleclick.net") {
		t.Error("выключено — не блокировать")
	}
}
