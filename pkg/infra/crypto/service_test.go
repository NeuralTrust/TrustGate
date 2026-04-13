package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validHexKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return hex.EncodeToString(key)
}

func TestNewEncryptionService(t *testing.T) {
	t.Run("valid 32-byte hex key", func(t *testing.T) {
		svc, err := NewEncryptionService(validHexKey(t))
		require.NoError(t, err)
		assert.IsType(t, &aesGCMService{}, svc)
	})

	t.Run("empty key returns nil", func(t *testing.T) {
		svc, err := NewEncryptionService("")
		require.NoError(t, err)
		assert.Nil(t, svc)
	})

	t.Run("invalid hex", func(t *testing.T) {
		_, err := NewEncryptionService("not-hex")
		assert.ErrorContains(t, err, "hex-encoded")
	})

	t.Run("wrong key length", func(t *testing.T) {
		_, err := NewEncryptionService(hex.EncodeToString([]byte("short")))
		assert.ErrorContains(t, err, "32 bytes")
	})
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	svc, err := NewEncryptionService(validHexKey(t))
	require.NoError(t, err)

	original := []byte(`{"type":"service_account","private_key":"-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n"}`)

	encrypted, err := svc.Encrypt(original)
	require.NoError(t, err)
	assert.NotEqual(t, original, encrypted)

	decrypted, err := svc.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, original, decrypted)
}

func TestDecryptWithWrongKey(t *testing.T) {
	svc1, err := NewEncryptionService(validHexKey(t))
	require.NoError(t, err)

	svc2, err := NewEncryptionService(validHexKey(t))
	require.NoError(t, err)

	encrypted, err := svc1.Encrypt([]byte("secret"))
	require.NoError(t, err)

	_, err = svc2.Decrypt(encrypted)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "decryption failed")
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	svc, err := NewEncryptionService(validHexKey(t))
	require.NoError(t, err)

	encrypted, err := svc.Encrypt([]byte("secret"))
	require.NoError(t, err)

	encrypted[len(encrypted)-1] ^= 0xff

	_, err = svc.Decrypt(encrypted)
	assert.Error(t, err)
}

func TestDecryptTooShort(t *testing.T) {
	svc, err := NewEncryptionService(validHexKey(t))
	require.NoError(t, err)

	_, err = svc.Decrypt([]byte("short"))
	assert.ErrorContains(t, err, "too short")
}
