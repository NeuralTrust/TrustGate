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

package ratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/redis/go-redis/v9"
)

const (
	burstKeyPattern = "gt:rl:burst:%s"
	quotaKeyPattern = "gt:rl:quota:%s:%s"
	burstWindow     = time.Minute
)

// Atomic INCR + PEXPIRE on first hit so counters never use get/set races.
var incrExpireScript = redis.NewScript(`
local n = redis.call("INCR", KEYS[1])
if n == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return n
`)

// Store is the Redis-backed plan counter (INCR).
type Store struct {
	redis  *redis.Client
	logger *slog.Logger
	now    func() time.Time
}

// NewStore creates a Redis counter store. Nil redis is treated as unavailable (caller fail-open).
func NewStore(rc *redis.Client, logger *slog.Logger) *Store {
	return &Store{redis: rc, logger: logger, now: time.Now}
}

func (s *Store) available() bool { return s != nil && s.redis != nil }

// IncrBurst atomically increments the 1-minute burst counter for a gateway.
func (s *Store) IncrBurst(ctx context.Context, gatewayID ids.GatewayID) (int64, time.Duration, error) {
	if !s.available() {
		return 0, 0, fmt.Errorf("redis unavailable")
	}
	key := fmt.Sprintf(burstKeyPattern, gatewayID.String())
	n, err := incrExpireScript.Run(ctx, s.redis, []string{key}, burstWindow.Milliseconds()).Int64()
	if err != nil {
		return 0, 0, err
	}
	ttl, err := s.redis.PTTL(ctx, key).Result()
	if err != nil {
		ttl = burstWindow
	}
	if ttl < 0 {
		ttl = burstWindow
	}
	return n, ttl, nil
}

// IncrQuota atomically increments the UTC monthly quota counter for a gateway.
func (s *Store) IncrQuota(ctx context.Context, gatewayID ids.GatewayID, month string) (int64, error) {
	if !s.available() {
		return 0, fmt.Errorf("redis unavailable")
	}
	key := fmt.Sprintf(quotaKeyPattern, gatewayID.String(), month)
	ttl := msUntilNextUTCMonth(s.now())
	return incrExpireScript.Run(ctx, s.redis, []string{key}, ttl).Int64()
}

func msUntilNextUTCMonth(now time.Time) int64 {
	now = now.UTC()
	next := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	ms := next.Sub(now).Milliseconds()
	if ms < 1 {
		return 1
	}
	return ms
}
