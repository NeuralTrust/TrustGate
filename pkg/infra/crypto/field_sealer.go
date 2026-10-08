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
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// SealedPrefix starts every value FieldSealer produces. The full form is
// "enc:v1:<key id>:<base64 nonce||ciphertext>".
const SealedPrefix = "enc:v1:"

// RegistrySecretsPurpose is the key purpose for credentials stored inside
// registry and auth configuration columns.
const RegistrySecretsPurpose = "registry-secrets/v1"

// ErrSealedValue reports a stored value that carries the sealed prefix but
// cannot be opened: malformed, sealed under another key, or tampered with.
var ErrSealedValue = errors.New("crypto: sealed value cannot be opened")

// FieldSealer encrypts single string fields of a JSON document so they can be
// stored in place. The caller's additional authenticated data names where the
// value lives (field and row), so a value copied anywhere else fails to open.
type FieldSealer struct {
	aead *PurposeAEAD
}

// NewFieldSealer derives the sealer's key from secret under purpose.
func NewFieldSealer(secret, purpose string) (*FieldSealer, error) {
	aead, err := NewPurposeAEAD(secret, purpose)
	if err != nil {
		return nil, err
	}
	return &FieldSealer{aead: aead}, nil
}

// KeyID identifies the key the sealer writes with.
func (s *FieldSealer) KeyID() string { return s.aead.KeyID() }

// IsSealed reports whether v has the sealed form.
func IsSealed(v string) bool { return strings.HasPrefix(v, SealedPrefix) }

// SealedKeyID returns the key id a sealed value names, or "" when v is not in
// the sealed form. It reads only the header, never the ciphertext.
func SealedKeyID(v string) string {
	if !IsSealed(v) {
		return ""
	}
	kid, _, _ := strings.Cut(strings.TrimPrefix(v, SealedPrefix), ":")
	return kid
}

// Seal encrypts plain bound to aad. An empty value stays empty so "unset"
// keeps its meaning.
func (s *FieldSealer) Seal(aad, plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	sealed, err := s.aead.Seal([]byte(plain), []byte(aad))
	if err != nil {
		return "", err
	}
	return SealedPrefix + s.aead.KeyID() + ":" + base64.StdEncoding.EncodeToString(sealed), nil
}

// Open returns the plaintext of a value Seal produced for aad. A value without
// the sealed prefix is returned unchanged, so rows written before sealing was
// introduced still read.
func (s *FieldSealer) Open(aad, stored string) (string, error) {
	if !IsSealed(stored) {
		return stored, nil
	}
	kid, encoded, ok := strings.Cut(strings.TrimPrefix(stored, SealedPrefix), ":")
	if !ok {
		return "", fmt.Errorf("%w: malformed", ErrSealedValue)
	}
	if kid != s.aead.KeyID() {
		return "", fmt.Errorf("%w: sealed under key %q, current key is %q", ErrSealedValue, kid, s.aead.KeyID())
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("%w: decode: %w", ErrSealedValue, err)
	}
	plain, err := s.aead.Open(raw, []byte(aad))
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrSealedValue, err)
	}
	return string(plain), nil
}
