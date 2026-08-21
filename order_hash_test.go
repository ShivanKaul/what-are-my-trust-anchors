package main

import "testing"

func TestOrderHashIsOrderSensitive(t *testing.T) {
	first := parseTrustAnchors([]byte{0x00, 0x0a, 0x04, 0x01, 0x02, 0x03, 0x04, 0x04, 0x05, 0x06, 0x07, 0x08})
	second := parseTrustAnchors([]byte{0x00, 0x0a, 0x04, 0x05, 0x06, 0x07, 0x08, 0x04, 0x01, 0x02, 0x03, 0x04})

	if first.ParseError != "" || second.ParseError != "" {
		t.Fatalf("unexpected parse error: first=%q second=%q", first.ParseError, second.ParseError)
	}
	if first.OrderHash == "" || second.OrderHash == "" {
		t.Fatal("expected non-empty ordering hashes")
	}
	if first.OrderHash == second.OrderHash {
		t.Fatal("expected different hashes for different anchor ordering")
	}
}
