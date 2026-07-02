package configsync

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
)

type stringCodec struct{}

func (stringCodec) Encode(snapshot string) ([]byte, error) {
	return []byte(snapshot), nil
}

func (stringCodec) Decode(raw []byte) (string, error) {
	return string(raw), nil
}

func (stringCodec) Version(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func newTestKey() []byte {
	key := make([]byte, aesKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

func writeCorrupt(path string) error {
	return os.WriteFile(path, []byte("not-a-valid-ciphertext"), 0o600)
}
