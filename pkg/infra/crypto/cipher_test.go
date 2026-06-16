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
	"strings"
	"testing"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func TestCipher_RoundTrip(t *testing.T) {
	t.Parallel()
	c, err := NewCipher(testSecret)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	plain := "gho_token_with_unicode_ñ"
	sealed, err := c.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if sealed == plain || strings.Contains(sealed, "token") {
		t.Fatal("ciphertext leaks plaintext")
	}
	got, err := c.Decrypt(sealed)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != plain {
		t.Fatalf("Decrypt = %q, want %q", got, plain)
	}
}

func TestCipher_EmptyValuesPassThrough(t *testing.T) {
	t.Parallel()
	c, _ := NewCipher(testSecret)
	if sealed, err := c.Encrypt(""); err != nil || sealed != "" {
		t.Fatalf("Encrypt(\"\") = %q, %v", sealed, err)
	}
	if plain, err := c.Decrypt(""); err != nil || plain != "" {
		t.Fatalf("Decrypt(\"\") = %q, %v", plain, err)
	}
}

func TestCipher_TamperedCiphertextFails(t *testing.T) {
	t.Parallel()
	c, _ := NewCipher(testSecret)
	sealed, _ := c.Encrypt("secret")
	if _, err := c.Decrypt(sealed[:len(sealed)-4] + "AAAA"); err == nil {
		t.Fatal("Decrypt of tampered ciphertext succeeded, want error")
	}
}

func TestCipher_WrongKeyFails(t *testing.T) {
	t.Parallel()
	c1, _ := NewCipher(testSecret)
	c2, _ := NewCipher("fedcba9876543210fedcba9876543210")
	sealed, _ := c1.Encrypt("secret")
	if _, err := c2.Decrypt(sealed); err == nil {
		t.Fatal("Decrypt with wrong key succeeded, want error")
	}
}

func TestNewCipher_RequiresSecret(t *testing.T) {
	t.Parallel()
	if _, err := NewCipher(""); err == nil {
		t.Fatal("NewCipher(\"\") = nil error, want failure")
	}
}

func TestNewCipher_RejectsShortSecret(t *testing.T) {
	t.Parallel()
	if _, err := NewCipher("too-short"); err == nil {
		t.Fatal("NewCipher with a short secret must fail: the key derivation has no KDF cost factor")
	}
}
