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

package configsnapshot

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func lkgSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestLKGSealer_RoundTripCompressesAndEncrypts(t *testing.T) {
	t.Parallel()
	s, err := NewLKGSealer(lkgSecret(t))
	if err != nil {
		t.Fatalf("NewLKGSealer: %v", err)
	}
	raw := bytes.Repeat([]byte("api-key-looking-text "), 5000)
	payload, err := s.Seal("scope", "v1", raw)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(payload) >= len(raw)/10 {
		t.Fatalf("payload %d bytes for %d raw: compression did not run before encryption", len(payload), len(raw))
	}
	if bytes.Contains(payload, []byte("api-key-looking-text")) {
		t.Fatal("payload leaks plaintext")
	}
	got, err := s.Open("scope", "v1", payload)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("Open mismatch: err=%v equal=%v", err, bytes.Equal(got, raw))
	}
}

func TestLKGSealer_RejectsForeignScopeVersionKeyAndTampering(t *testing.T) {
	t.Parallel()
	secret := lkgSecret(t)
	s, _ := NewLKGSealer(secret)
	other, _ := NewLKGSealer(lkgSecret(t))
	payload, _ := s.Seal("scope-a", "v1", []byte("snapshot"))

	if _, err := s.Open("scope-b", "v1", payload); err == nil {
		t.Fatal("a payload moved to another scope must not open")
	}
	if _, err := s.Open("scope-a", "v2", payload); err == nil {
		t.Fatal("a payload paired with another version must not open")
	}
	if _, err := other.Open("scope-a", "v1", payload); err == nil {
		t.Fatal("a payload sealed under another secret must not open")
	}
	if s.KeyID() == other.KeyID() {
		t.Fatal("different secrets must have different key ids")
	}
	payload[0] ^= 0xff
	if _, err := s.Open("scope-a", "v1", payload); err == nil {
		t.Fatal("a tampered payload must not open")
	}
}

func TestLKGSealer_GlobalScopeIsBoundToo(t *testing.T) {
	t.Parallel()
	s, _ := NewLKGSealer(lkgSecret(t))
	payload, _ := s.Seal("", "v1", []byte("global"))
	if _, err := s.Open("gw", "v1", payload); err == nil {
		t.Fatal("the global payload must not open as a scoped row")
	}
	if got, err := s.Open("", "v1", payload); err != nil || string(got) != "global" {
		t.Fatalf("Open global = %q, %v", got, err)
	}
}

func TestLKGSealer_RejectsAnAuthenticatedPayloadThatDecompressesPastTheCap(t *testing.T) {
	t.Parallel()
	s, _ := NewLKGSealer(lkgSecret(t))
	// Zeros compress to a few bytes, so the payload is tiny but expands past the
	// cap. It is built at run time and authenticates correctly.
	big := make([]byte, lkgMaxDecoded+1<<20)
	payload, err := s.Seal("scope", "v1", big)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(payload) > 1<<20 {
		t.Fatalf("setup: payload is %d bytes, expected a tiny compressed one", len(payload))
	}
	if _, err := s.Open("scope", "v1", payload); err == nil {
		t.Fatal("a payload that decompresses past the cap must be rejected")
	}
}
