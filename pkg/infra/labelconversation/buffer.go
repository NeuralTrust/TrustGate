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

// Package labelconversation stores the encrypted per-conversation user message
// buffer traffic labels use to label OpenAI Responses continuations.
package labelconversation

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/trafficlabels"
	"github.com/redis/go-redis/v9"
)

const (
	keyPrefix  = "trafficlabels:conversation:"
	defaultTTL = time.Hour

	// KeyLen is the length of the secret New expects: an AES-256 key followed
	// by an HMAC-SHA256 key for the Redis key names.
	KeyLen    = 64
	aesKeyLen = 32
)

var (
	ErrInvalidKey = errors.New("labelconversation: key must be 64 bytes")

	_ trafficlabels.ConversationBuffer = (*Buffer)(nil)
)

// Buffer keeps each conversation's recent user messages in Redis, sealed with
// AES-256-GCM and bound to their key, under an HMAC-derived key name so the
// session ids never appear in Redis. Every Save restarts the TTL.
type Buffer struct {
	redis   redis.Cmdable
	ttl     time.Duration
	aead    cipher.AEAD
	nameKey []byte
}

func New(client redis.Cmdable, ttl time.Duration, key []byte) (*Buffer, error) {
	if len(key) != KeyLen {
		return nil, ErrInvalidKey
	}
	if ttl <= 0 {
		ttl = defaultTTL
	}
	block, err := aes.NewCipher(key[:aesKeyLen])
	if err != nil {
		return nil, fmt.Errorf("labelconversation: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("labelconversation: %w", err)
	}
	return &Buffer{redis: client, ttl: ttl, aead: aead, nameKey: append([]byte(nil), key[aesKeyLen:]...)}, nil
}

func (b *Buffer) Load(ctx context.Context, key trafficlabels.ConversationKey) ([]string, error) {
	name := b.redisKey(key)
	sealed, err := b.redis.Get(ctx, name).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("labelconversation: get: %w", err)
	}
	ns := b.aead.NonceSize()
	if len(sealed) < ns {
		return nil, errors.New("labelconversation: ciphertext too short")
	}
	plain, err := b.aead.Open(nil, sealed[:ns], sealed[ns:], []byte(name))
	if err != nil {
		return nil, fmt.Errorf("labelconversation: open: %w", err)
	}
	var msgs []string
	if err := json.Unmarshal(plain, &msgs); err != nil {
		return nil, fmt.Errorf("labelconversation: decode: %w", err)
	}
	return msgs, nil
}

func (b *Buffer) Save(ctx context.Context, key trafficlabels.ConversationKey, messages []string) error {
	plain, err := json.Marshal(messages)
	if err != nil {
		return fmt.Errorf("labelconversation: encode: %w", err)
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("labelconversation: nonce: %w", err)
	}
	name := b.redisKey(key)
	sealed := b.aead.Seal(nonce, nonce, plain, []byte(name))
	if err := b.redis.Set(ctx, name, sealed, b.ttl).Err(); err != nil {
		return fmt.Errorf("labelconversation: set: %w", err)
	}
	return nil
}

func (b *Buffer) redisKey(key trafficlabels.ConversationKey) string {
	mac := hmac.New(sha256.New, b.nameKey)
	for _, part := range []string{key.GatewayID, key.ConsumerID, key.SessionID} {
		mac.Write([]byte(part))
		mac.Write([]byte{0})
	}
	return keyPrefix + hex.EncodeToString(mac.Sum(nil))
}
