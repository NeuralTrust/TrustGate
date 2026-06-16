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

package consumer

import (
	"crypto/rand"
	"fmt"
)

const (
	slugLength   = 8
	slugAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

// NewSlug returns a short, URL-safe, random consumer alias (e.g. "X84Yhsy8").
// 62^8 combinations make collisions vanishingly rare; the unique index plus a
// retry on save covers the residual risk.
func NewSlug() (string, error) {
	// Rejection sampling: bytes >= 248 (62*4) are discarded so every alphabet
	// character is equally likely (plain modulo would bias the first 8 chars).
	const maxUnbiased = byte(len(slugAlphabet) * (256 / len(slugAlphabet)))
	out := make([]byte, 0, slugLength)
	buf := make([]byte, slugLength*2)
	for {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("consumer: generate slug: %w", err)
		}
		for _, b := range buf {
			if b >= maxUnbiased {
				continue
			}
			out = append(out, slugAlphabet[int(b)%len(slugAlphabet)])
			if len(out) == slugLength {
				return string(out), nil
			}
		}
	}
}

func IsValidSlug(s string) bool {
	if len(s) != slugLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}
