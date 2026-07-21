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

package crypto

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"

	"github.com/redis/go-redis/v9"
)

// SharedSecretKeyRedisKey is the Redis key under which the auto-provisioned
// SERVER_SECRET_KEY is stored so every replica encrypts vault material and
// verifies admin-plane JWTs with the same secret.
const SharedSecretKeyRedisKey = "trustgate:server:secret-key"

const sharedSecretBytes = 32

// ResolveSharedSecretKey returns a base64-encoded secret shared across replicas
// via Redis. It returns the stored secret when present; otherwise it generates
// one and stores it with SETNX so concurrent replicas converge on a single
// value instead of each minting with its own ephemeral secret.
func ResolveSharedSecretKey(ctx context.Context, rdb *redis.Client, logger *slog.Logger) (string, error) {
	if rdb == nil {
		return "", errors.New("crypto: redis client is required to auto-provision SERVER_SECRET_KEY")
	}
	if existing, err := rdb.Get(ctx, SharedSecretKeyRedisKey).Result(); err == nil && existing != "" {
		return existing, nil
	} else if err != nil && !errors.Is(err, redis.Nil) {
		return "", fmt.Errorf("crypto: read shared secret key: %w", err)
	}
	generated, err := generateSecretKey()
	if err != nil {
		return "", err
	}
	won, err := rdb.SetNX(ctx, SharedSecretKeyRedisKey, generated, 0).Result()
	if err != nil {
		return "", fmt.Errorf("crypto: persist shared secret key: %w", err)
	}
	if won {
		if logger != nil {
			logger.Info("crypto: auto-provisioned shared SERVER_SECRET_KEY in redis")
		}
		return generated, nil
	}
	stored, err := rdb.Get(ctx, SharedSecretKeyRedisKey).Result()
	if err != nil {
		return "", fmt.Errorf("crypto: read shared secret key after race: %w", err)
	}
	return stored, nil
}

func generateSecretKey() (string, error) {
	buf := make([]byte, sharedSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("crypto: generate secret key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}
