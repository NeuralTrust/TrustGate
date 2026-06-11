// Package crypto provides authenticated encryption for secrets at rest
// (vaulted third-party tokens). AES-256-GCM with a key derived from the
// server secret; swap the key source for KMS/secret-manager in production
// per the cross-cutting secret rules.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

type Cipher struct {
	aead cipher.AEAD
}

// NewCipher derives a 256-bit key from the secret. The secret must be
// non-empty: storing third-party refresh tokens unencrypted is not an option.
func NewCipher(secret string) (*Cipher, error) {
	if secret == "" {
		return nil, errors.New("crypto: encryption secret is required (set SERVER_SECRET_KEY)")
	}
	key := sha256.Sum256([]byte("agentgateway-vault:" + secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt seals the plaintext and returns base64(nonce || ciphertext).
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("crypto: nonce: %w", err)
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt reverses Encrypt.
func (c *Cipher) Decrypt(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("crypto: decode: %w", err)
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("crypto: ciphertext too short")
	}
	plain, err := c.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("crypto: open: %w", err)
	}
	return string(plain), nil
}
