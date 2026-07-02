package configsync

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAESGCMCrypto_KeySize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		keyLen  int
		wantErr bool
	}{
		{name: "32-byte key ok", keyLen: 32},
		{name: "31-byte key rejected", keyLen: 31, wantErr: true},
		{name: "33-byte key rejected", keyLen: 33, wantErr: true},
		{name: "empty key rejected", keyLen: 0, wantErr: true},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewAESGCMCrypto(make([]byte, tc.keyLen))
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestAESGCMCrypto_Roundtrip(t *testing.T) {
	t.Parallel()

	crypto, err := NewAESGCMCrypto(newTestKey())
	require.NoError(t, err)

	plaintext := []byte("last-known-good snapshot payload")
	ciphertext, err := crypto.Encrypt(plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := crypto.Decrypt(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAESGCMCrypto_UniqueNonce(t *testing.T) {
	t.Parallel()

	crypto, err := NewAESGCMCrypto(newTestKey())
	require.NoError(t, err)

	first, err := crypto.Encrypt([]byte("same"))
	require.NoError(t, err)
	second, err := crypto.Encrypt([]byte("same"))
	require.NoError(t, err)
	assert.False(t, bytes.Equal(first, second))
}

func TestAESGCMCrypto_TamperRejected(t *testing.T) {
	t.Parallel()

	crypto, err := NewAESGCMCrypto(newTestKey())
	require.NoError(t, err)

	ciphertext, err := crypto.Encrypt([]byte("payload"))
	require.NoError(t, err)
	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err = crypto.Decrypt(ciphertext)
	require.Error(t, err)
}

func TestAESGCMCrypto_WrongKeyRejected(t *testing.T) {
	t.Parallel()

	encryptCrypto, err := NewAESGCMCrypto(newTestKey())
	require.NoError(t, err)
	ciphertext, err := encryptCrypto.Encrypt([]byte("payload"))
	require.NoError(t, err)

	otherKey := newTestKey()
	otherKey[0] ^= 0xFF
	decryptCrypto, err := NewAESGCMCrypto(otherKey)
	require.NoError(t, err)

	_, err = decryptCrypto.Decrypt(ciphertext)
	require.Error(t, err)
}

func TestAESGCMCrypto_ShortCiphertextRejected(t *testing.T) {
	t.Parallel()

	crypto, err := NewAESGCMCrypto(newTestKey())
	require.NoError(t, err)

	_, err = crypto.Decrypt([]byte{0x00})
	require.Error(t, err)
}
