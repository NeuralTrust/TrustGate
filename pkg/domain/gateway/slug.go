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

package gateway

import (
	"crypto/rand"
	"fmt"
)

const (
	generatedSlugPrefix   = "gw-"
	generatedSlugRandLen  = 12
	generatedSlugAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// NewSlug returns a random gateway slug that satisfies the DNS-label format
// (e.g. "gw-k3f9x1a2b7c4"). 36^12 combinations make collisions vanishingly
// rare; the slug unique index plus a retry on save covers the residual risk.
func NewSlug() (string, error) {
	// Rejection sampling: bytes >= 252 (36*7) are discarded so every alphabet
	// character is equally likely (plain modulo would bias the first chars).
	const maxUnbiased = byte(len(generatedSlugAlphabet) * (256 / len(generatedSlugAlphabet)))
	out := make([]byte, 0, generatedSlugRandLen)
	buf := make([]byte, generatedSlugRandLen*2)
	for {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("gateway: generate slug: %w", err)
		}
		for _, b := range buf {
			if b >= maxUnbiased {
				continue
			}
			out = append(out, generatedSlugAlphabet[int(b)%len(generatedSlugAlphabet)])
			if len(out) == generatedSlugRandLen {
				return generatedSlugPrefix + string(out), nil
			}
		}
	}
}
