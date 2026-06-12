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

// minSecretLen guards against low-entropy secrets: the AES key is derived
// with a single unsalted SHA-256, so a short or guessable secret would make
// the vault ciphertexts brute-forceable offline.
const minSecretLen = 32

func NewCipher(secret string) (*Cipher, error) {
	if secret == "" {
		return nil, errors.New("crypto: encryption secret is required (set SERVER_SECRET_KEY)")
	}
	if len(secret) < minSecretLen {
		return nil, fmt.Errorf("crypto: encryption secret must be at least %d bytes of random data (got %d)", minSecretLen, len(secret))
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
