// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func randomSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestPurposeAEAD_RoundTripBindsAAD(t *testing.T) {
	t.Parallel()
	p, err := NewPurposeAEAD(randomSecret(t), "unit")
	if err != nil {
		t.Fatalf("NewPurposeAEAD: %v", err)
	}
	sealed, err := p.Seal([]byte("payload"), []byte("a|1"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(sealed, []byte("payload")) {
		t.Fatal("ciphertext leaks plaintext")
	}
	got, err := p.Open(sealed, []byte("a|1"))
	if err != nil || string(got) != "payload" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	if _, err := p.Open(sealed, []byte("b|1")); err == nil {
		t.Fatal("a different aad must fail to open")
	}
	sealed[len(sealed)-1] ^= 0xff
	if _, err := p.Open(sealed, []byte("a|1")); err == nil {
		t.Fatal("a tampered ciphertext must fail to open")
	}
}

func TestPurposeAEAD_PurposesAndSecretsDoNotShareKeys(t *testing.T) {
	t.Parallel()
	secret := randomSecret(t)
	a, _ := NewPurposeAEAD(secret, "one")
	b, _ := NewPurposeAEAD(secret, "two")
	c, _ := NewPurposeAEAD(randomSecret(t), "one")
	again, _ := NewPurposeAEAD(secret, "one")

	if a.KeyID() == b.KeyID() || a.KeyID() == c.KeyID() {
		t.Fatalf("key ids must differ across purpose and secret: %s %s %s", a.KeyID(), b.KeyID(), c.KeyID())
	}
	if a.KeyID() != again.KeyID() {
		t.Fatal("the same secret and purpose must derive the same key id")
	}
	sealed, _ := a.Seal([]byte("x"), nil)
	if _, err := b.Open(sealed, nil); err == nil {
		t.Fatal("another purpose must not open the ciphertext")
	}
	if _, err := again.Open(sealed, nil); err != nil {
		t.Fatalf("the same purpose must open it: %v", err)
	}

	// The vault key must not be reusable here: sealing under the vault cipher
	// never opens under a purpose key.
	vault, _ := NewCipher(secret)
	enc, _ := vault.Encrypt("x")
	raw, _ := base64.StdEncoding.DecodeString(enc)
	if _, err := a.Open(raw, nil); err == nil {
		t.Fatal("a purpose key must differ from the vault key")
	}
}

func TestPurposeAEAD_RejectsBadInput(t *testing.T) {
	t.Parallel()
	if _, err := NewPurposeAEAD("", "p"); err == nil {
		t.Fatal("empty secret must fail")
	}
	if _, err := NewPurposeAEAD("short", "p"); err == nil {
		t.Fatal("short secret must fail")
	}
	if _, err := NewPurposeAEAD(randomSecret(t), ""); err == nil {
		t.Fatal("empty purpose must fail")
	}
	p, _ := NewPurposeAEAD(randomSecret(t), "p")
	if _, err := p.Open([]byte("tiny"), nil); err == nil {
		t.Fatal("a ciphertext shorter than the nonce must fail")
	}
}
