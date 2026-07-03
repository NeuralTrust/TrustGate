package configsync

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const aesKeySize = 32

type AESGCMCrypto struct {
	aead cipher.AEAD
}

func NewAESGCMCrypto(key []byte) (*AESGCMCrypto, error) {
	if len(key) != aesKeySize {
		return nil, fmt.Errorf("configsync: aes-256-gcm requires a %d-byte key, got %d", aesKeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("configsync: new aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("configsync: new gcm: %w", err)
	}
	return &AESGCMCrypto{aead: aead}, nil
}

func (c *AESGCMCrypto) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("configsync: generate nonce: %w", err)
	}
	return c.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (c *AESGCMCrypto) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("configsync: ciphertext shorter than nonce")
	}
	nonce, sealed := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := c.aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("configsync: decrypt: %w", err)
	}
	return plaintext, nil
}
