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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

const purposeKeyLen = 32

// PurposeAEAD is an AES-256-GCM sealer over raw bytes whose key is derived from
// the server secret under a purpose label. Two purposes never share a key, and
// none shares the vault key that NewCipher derives, so a ciphertext produced for
// one purpose cannot be opened under another and a compromise of one derived key
// does not expose the others.
type PurposeAEAD struct {
	aead  cipher.AEAD
	keyID string
}

// NewPurposeAEAD derives the key for purpose from secret with HKDF-SHA256. The
// secret must satisfy the same minimum as NewCipher.
func NewPurposeAEAD(secret, purpose string) (*PurposeAEAD, error) {
	if secret == "" {
		return nil, errors.New("crypto: encryption secret is required (set SERVER_SECRET_KEY)")
	}
	if len(secret) < minSecretLen {
		return nil, fmt.Errorf("crypto: encryption secret must be at least %d bytes of random data (got %d)", minSecretLen, len(secret))
	}
	if purpose == "" {
		return nil, errors.New("crypto: purpose label is required")
	}
	key, err := hkdf.Key(sha256.New, []byte(secret), nil, "trustgate:"+purpose, purposeKeyLen)
	if err != nil {
		return nil, fmt.Errorf("crypto: derive key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: %w", err)
	}
	// The id is a one-way hash of the derived key under its own label, so it
	// identifies the key in a stored row without revealing it.
	sum := sha256.Sum256(append([]byte("trustgate:key-id:"), key...))
	return &PurposeAEAD{aead: aead, keyID: hex.EncodeToString(sum[:8])}, nil
}

// KeyID is a short stable identifier of the derived key.
func (p *PurposeAEAD) KeyID() string { return p.keyID }

// Seal encrypts plaintext and binds aad to it. The output is nonce || ciphertext.
func (p *PurposeAEAD) Seal(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, p.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: nonce: %w", err)
	}
	return p.aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Open reverses Seal. It fails when the key, the aad or any byte differ.
func (p *PurposeAEAD) Open(sealed, aad []byte) ([]byte, error) {
	ns := p.aead.NonceSize()
	if len(sealed) < ns {
		return nil, errors.New("crypto: ciphertext too short")
	}
	plain, err := p.aead.Open(nil, sealed[:ns], sealed[ns:], aad)
	if err != nil {
		return nil, fmt.Errorf("crypto: open: %w", err)
	}
	return plain, nil
}
