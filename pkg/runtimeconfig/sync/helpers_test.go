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
