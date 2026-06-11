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
