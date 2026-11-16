package main

import (
	"testing"
	"time"
)

func TestShareSendReceive(t *testing.T) {
	rx := NewShare(t.Logf)
	rx.Listen()
	time.Sleep(200 * time.Millisecond)
	tx := NewShare(t.Logf)
	tx.Name = "Телефон"
	if err := tx.Send("127.0.0.1", "Bridge obfs4 1.2.3.4:443 FP cert=x iat-mode=0\n\nwebtunnel [::1]:443 FP url=https://x/y"); err != nil {
		t.Fatal(err)
	}
	o := rx.Offer()
	if o == nil || o.Count != 2 || o.From != "Телефон" {
		t.Fatalf("предложение: %+v", o)
	}
	if _, ok := rx.Take("чужой"); ok {
		t.Fatal("взято по неверному id")
	}
	text, ok := rx.Take(o.ID)
	if !ok || len(splitBridgeLines(text)) != 2 || rx.Offer() != nil {
		t.Fatalf("Take: %q %v", text, ok)
	}
}
