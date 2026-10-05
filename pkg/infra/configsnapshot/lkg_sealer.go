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
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	"github.com/klauspost/compress/zstd"
)

const (
	lkgPurpose = "config-snapshot-lkg/v1"
	// lkgMaxDecoded bounds the decompressed size so a payload that authenticates
	// but expands without limit cannot exhaust the admin (limit 1Gi). A real
	// snapshot is about 1.7 MB per scope.
	lkgMaxDecoded = 64 << 20
)

// LKGSealer compresses a snapshot with zstd, then encrypts it with AES-256-GCM
// under a key derived from the server secret for this purpose alone. It
// compresses first because ciphertext does not compress. Scope and version are
// the additional authenticated data, so a payload copied to another row, or
// paired with another version, fails to open.
type LKGSealer struct {
	aead *crypto.PurposeAEAD
	enc  *zstd.Encoder
	dec  *zstd.Decoder
}

// NewLKGSealer builds the sealer from the server secret.
func NewLKGSealer(secret string) (*LKGSealer, error) {
	aead, err := crypto.NewPurposeAEAD(secret, lkgPurpose)
	if err != nil {
		return nil, fmt.Errorf("configsnapshot: lkg sealer: %w", err)
	}
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, fmt.Errorf("configsnapshot: lkg zstd encoder: %w", err)
	}
	dec, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(lkgMaxDecoded))
	if err != nil {
		return nil, fmt.Errorf("configsnapshot: lkg zstd decoder: %w", err)
	}
	return &LKGSealer{aead: aead, enc: enc, dec: dec}, nil
}

// KeyID identifies the derived key.
func (s *LKGSealer) KeyID() string { return s.aead.KeyID() }

func lkgAAD(scope, version string) []byte { return []byte(scope + "|" + version) }

// Seal compresses and encrypts raw for the row (scope, version).
func (s *LKGSealer) Seal(scope, version string, raw []byte) ([]byte, error) {
	compressed := s.enc.EncodeAll(raw, nil)
	return s.aead.Seal(compressed, lkgAAD(scope, version))
}

// Open decrypts and decompresses a payload sealed for (scope, version).
func (s *LKGSealer) Open(scope, version string, payload []byte) ([]byte, error) {
	compressed, err := s.aead.Open(payload, lkgAAD(scope, version))
	if err != nil {
		return nil, err
	}
	raw, err := s.dec.DecodeAll(compressed, nil)
	if err != nil {
		return nil, fmt.Errorf("configsnapshot: lkg decompress: %w", err)
	}
	return raw, nil
}
