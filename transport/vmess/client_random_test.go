package vmess

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDeriveClientRandom(t *testing.T) {
	key, _ := hex.DecodeString("aabbccddeeff00112233445566778899")
	salt, _ := hex.DecodeString("11223344556677889900112233445566")
	expected, _ := hex.DecodeString("112233445566778899001122334455669591807266c901dfe8c73c3040b1bd82")
	got, err := deriveClientRandom(key, "abcd", salt)
	if err != nil || !bytes.Equal(got, expected) {
		t.Fatalf("derived client random does not match upstream vector: %v", err)
	}
	key[0] ^= 0xff
	wrong, err := deriveClientRandom(key, "abcd", salt)
	if err != nil || bytes.Equal(wrong, expected) {
		t.Fatalf("altered key matched upstream vector: %v", err)
	}
}
