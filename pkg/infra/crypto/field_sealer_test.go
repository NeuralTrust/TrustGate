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
	"errors"
	"strings"
	"testing"
)

func TestFieldSealer_RoundTrip(t *testing.T) {
	t.Parallel()
	s, err := NewFieldSealer(randomSecret(t), RegistrySecretsPurpose)
	if err != nil {
		t.Fatalf("NewFieldSealer: %v", err)
	}
	sealed, err := s.Seal("auth.value", "Bearer abc")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if !strings.HasPrefix(sealed, SealedPrefix+s.KeyID()+":") || !IsSealed(sealed) {
		t.Fatalf("sealed form = %q", sealed)
	}
	if strings.Contains(sealed, "abc") {
		t.Fatal("sealed value must not contain the plaintext")
	}
	got, err := s.Open("auth.value", sealed)
	if err != nil || got != "Bearer abc" {
		t.Fatalf("Open = %q, %v", got, err)
	}
	again, _ := s.Seal("auth.value", "Bearer abc")
	if again == sealed {
		t.Fatal("each seal must use a fresh nonce")
	}
}

func TestFieldSealer_EmptyAndLegacyValues(t *testing.T) {
	t.Parallel()
	s, _ := NewFieldSealer(randomSecret(t), RegistrySecretsPurpose)
	if sealed, err := s.Seal("f", ""); err != nil || sealed != "" {
		t.Fatalf("empty Seal = %q, %v", sealed, err)
	}
	if got, err := s.Open("f", "legacy-value"); err != nil || got != "legacy-value" {
		t.Fatalf("legacy Open = %q, %v", got, err)
	}
}

func TestFieldSealer_RefusesOtherFieldKeyOrTamper(t *testing.T) {
	t.Parallel()
	secret := randomSecret(t)
	s, _ := NewFieldSealer(secret, RegistrySecretsPurpose)
	other, _ := NewFieldSealer(randomSecret(t), RegistrySecretsPurpose)
	sealed, _ := s.Seal("a", "value")

	if _, err := s.Open("b", sealed); !errors.Is(err, ErrSealedValue) {
		t.Fatalf("other field: err = %v", err)
	}
	if _, err := other.Open("a", sealed); !errors.Is(err, ErrSealedValue) {
		t.Fatalf("other key: err = %v", err)
	}
	if _, err := s.Open("a", SealedPrefix+"nokid"); !errors.Is(err, ErrSealedValue) {
		t.Fatalf("malformed: err = %v", err)
	}
	tampered := sealed[:len(sealed)-2] + "AA"
	if tampered == sealed {
		tampered = sealed[:len(sealed)-2] + "BB"
	}
	if _, err := s.Open("a", tampered); !errors.Is(err, ErrSealedValue) {
		t.Fatalf("tampered: err = %v", err)
	}
}

func TestSealedKeyID(t *testing.T) {
	t.Parallel()
	s, _ := NewFieldSealer(randomSecret(t), RegistrySecretsPurpose)
	sealed, _ := s.Seal("a", "value")
	if got := SealedKeyID(sealed); got != s.KeyID() {
		t.Fatalf("SealedKeyID = %q, want %q", got, s.KeyID())
	}
	if got := SealedKeyID("plain"); got != "" {
		t.Fatalf("SealedKeyID(plain) = %q", got)
	}
}

func TestFieldSealer_OpenFieldAndCanOpen(t *testing.T) {
	t.Parallel()
	s, _ := NewFieldSealer(randomSecret(t), RegistrySecretsPurpose)
	aad := FieldAAD("table.field", "row-1")
	if aad != "table.field|row-1" {
		t.Fatalf("FieldAAD = %q", aad)
	}
	sealed, _ := s.Seal(aad, "value")

	if got, err := s.OpenField(aad, sealed); err != nil || got != "value" {
		t.Fatalf("OpenField = %q, %v", got, err)
	}
	if !s.CanOpen(aad, sealed) || s.CanOpen(FieldAAD("table.field", "row-2"), sealed) {
		t.Fatal("CanOpen must follow the aad")
	}

	var none *FieldSealer
	if got, err := none.OpenField(aad, "plain"); err != nil || got != "plain" {
		t.Fatalf("nil sealer, plain value: %q, %v", got, err)
	}
	if _, err := none.OpenField(aad, sealed); !errors.Is(err, ErrNoFieldSealer) {
		t.Fatalf("nil sealer, sealed value: err = %v", err)
	}
	if none.CanOpen(aad, sealed) || !none.CanOpen(aad, "plain") {
		t.Fatal("nil sealer: only unsealed values open")
	}
}
