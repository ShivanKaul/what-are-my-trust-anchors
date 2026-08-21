package main

import (
	"encoding/hex"
	"testing"
)

func TestParseTrustAnchorsEmpty(t *testing.T) {
	got := parseTrustAnchors([]byte{0x00, 0x00})
	if !got.Present || !got.Empty || got.ParseError != "" || len(got.Anchors) != 0 {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestParseTrustAnchorsIDs(t *testing.T) {
	data, _ := hex.DecodeString("000b0481fd59010581fd590201")
	got := parseTrustAnchors(data)
	if got.ParseError != "" {
		t.Fatal(got.ParseError)
	}
	if len(got.Anchors) != 2 {
		t.Fatalf("got %d anchors", len(got.Anchors))
	}
	if got.Anchors[0].RelativeOID != "32473.1" {
		t.Fatalf("got %q", got.Anchors[0].RelativeOID)
	}
	if got.Anchors[1].RelativeOID != "32473.2.1" {
		t.Fatalf("got %q", got.Anchors[1].RelativeOID)
	}
}

func TestDecodeRelativeOID(t *testing.T) {
	raw, _ := hex.DecodeString("81fd5901")
	got, err := decodeRelativeOID(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != "32473.1" {
		t.Fatalf("got %q", got)
	}
}
