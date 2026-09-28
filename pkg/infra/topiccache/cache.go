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

// Package topiccache keeps topic classifications in Redis so repeated prompts
// are not sent to topic-guard again.
package topiccache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/topicclassifier"
	"github.com/NeuralTrust/TrustGate/pkg/domain/topic"
	"github.com/redis/go-redis/v9"
)

const (
	keyPrefix  = "topicclassifier:cache:"
	defaultTTL = time.Hour
)

var _ topicclassifier.Cache = (*Cache)(nil)

// Cache stores classifications under topic.CacheKey with a fixed TTL.
type Cache struct {
	redis redis.Cmdable
	ttl   time.Duration
}

// New builds a Cache. A non-positive ttl falls back to one hour.
func New(client redis.Cmdable, ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = defaultTTL
	}
	return &Cache{redis: client, ttl: ttl}
}

// Get returns the classification stored under key, and whether there was one.
func (c *Cache) Get(ctx context.Context, key string) (topic.Classification, bool, error) {
	raw, err := c.redis.Get(ctx, keyPrefix+key).Bytes()
	if errors.Is(err, redis.Nil) {
		return topic.Classification{}, false, nil
	}
	if err != nil {
		return topic.Classification{}, false, fmt.Errorf("topiccache: get: %w", err)
	}
	var out topic.Classification
	if err := json.Unmarshal(raw, &out); err != nil {
		return topic.Classification{}, false, fmt.Errorf("topiccache: decode: %w", err)
	}
	return out, true, nil
}

// Set stores the classification under key for the cache TTL.
func (c *Cache) Set(ctx context.Context, key string, cls topic.Classification) error {
	raw, err := json.Marshal(cls)
	if err != nil {
		return fmt.Errorf("topiccache: encode: %w", err)
	}
	if err := c.redis.Set(ctx, keyPrefix+key, raw, c.ttl).Err(); err != nil {
		return fmt.Errorf("topiccache: set: %w", err)
	}
	return nil
}
