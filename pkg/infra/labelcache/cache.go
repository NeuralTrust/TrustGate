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

package labelcache

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/trafficlabels"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
	"github.com/redis/go-redis/v9"
)

const (
	keyPrefix  = "trafficlabels:cache:"
	defaultTTL = time.Hour
)

var _ trafficlabels.Cache = (*Cache)(nil)

type Cache struct {
	redis  redis.Cmdable
	ttl    time.Duration
	secret []byte
}

func New(client redis.Cmdable, ttl time.Duration, secret []byte) *Cache {
	if ttl <= 0 {
		ttl = defaultTTL
	}
	return &Cache{redis: client, ttl: ttl, secret: secret}
}

func (c *Cache) redisKey(key string) string {
	mac := hmac.New(sha256.New, c.secret)
	mac.Write([]byte(key))
	return keyPrefix + hex.EncodeToString(mac.Sum(nil))
}

func (c *Cache) GetMany(ctx context.Context, keys []string) (map[string]trafficlabel.Classification, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	pipe := c.redis.Pipeline()
	cmds := make([]*redis.StringCmd, len(keys))
	for i, key := range keys {
		cmds[i] = pipe.Get(ctx, c.redisKey(key))
	}
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return nil, fmt.Errorf("labelcache: get: %w", err)
	}
	out := make(map[string]trafficlabel.Classification, len(keys))
	for i, cmd := range cmds {
		raw, err := cmd.Bytes()
		if err != nil {
			continue
		}
		var cls trafficlabel.Classification
		if json.Unmarshal(raw, &cls) != nil {
			continue
		}
		out[keys[i]] = cls
	}
	return out, nil
}

func (c *Cache) SetMany(ctx context.Context, entries map[string]trafficlabel.Classification) error {
	if len(entries) == 0 {
		return nil
	}
	pipe := c.redis.Pipeline()
	for key, cls := range entries {
		raw, err := json.Marshal(cls)
		if err != nil {
			return fmt.Errorf("labelcache: encode: %w", err)
		}
		pipe.Set(ctx, c.redisKey(key), raw, c.ttl)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("labelcache: set: %w", err)
	}
	return nil
}
