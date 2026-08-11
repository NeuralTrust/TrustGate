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

package sts

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"

	"github.com/redis/go-redis/v9"
)

// SharedSigningKeyRedisKey is the Redis key under which the auto-provisioned STS
// signing key is stored so every replica signs and verifies with the same key.
const SharedSigningKeyRedisKey = "trustgate:sts:signing-key:pkcs8-pem"

// ResolveSharedSigningKey returns a PEM-encoded RSA signing key shared across
// replicas via Redis. It returns the stored key when present; otherwise it
// generates one and stores it with SETNX so concurrent replicas converge on a
// single key instead of each minting with its own ephemeral key.
func ResolveSharedSigningKey(ctx context.Context, rdb *redis.Client, logger *slog.Logger) (string, error) {
	if rdb == nil {
		return "", errors.New("sts: redis client is required to auto-provision a signing key")
	}
	if existing, err := rdb.Get(ctx, SharedSigningKeyRedisKey).Result(); err == nil && existing != "" {
		return existing, nil
	} else if err != nil && !errors.Is(err, redis.Nil) {
		return "", fmt.Errorf("sts: read shared signing key: %w", err)
	}
	generated, err := generateSigningKeyPEM()
	if err != nil {
		return "", err
	}
	won, err := rdb.SetNX(ctx, SharedSigningKeyRedisKey, generated, 0).Result()
	if err != nil {
		return "", fmt.Errorf("sts: persist shared signing key: %w", err)
	}
	if won {
		if logger != nil {
			logger.Info("sts: auto-provisioned shared STS signing key in redis")
		}
		return generated, nil
	}
	stored, err := rdb.Get(ctx, SharedSigningKeyRedisKey).Result()
	if err != nil {
		return "", fmt.Errorf("sts: read shared signing key after race: %w", err)
	}
	return stored, nil
}

func generateSigningKeyPEM() (string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("sts: generate signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("sts: marshal signing key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}
