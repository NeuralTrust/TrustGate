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

// Package usage persists usage states in Redis for control plane cold starts.
package usage

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/usage"
)

// StatesKey is the hash holding one field per tenant. A single key loads with
// one HGETALL at boot and lives in one cluster slot.
const StatesKey = "gt:usage:states"

// saveScript stores ARGV[2] under field ARGV[1] unless the field already holds
// a version (the prefix before the first '|') at least ARGV[3]. Several control
// plane replicas write the same states, so a late older write must never
// replace a newer one.
var saveScript = redis.NewScript(`
local current = redis.call('HGET', KEYS[1], ARGV[1])
if current then
  local version = tonumber(string.match(current, '^(%d+)|'))
  if version and version >= tonumber(ARGV[3]) then
    return 0
  end
end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
return 1
`)

// RedisStateCache is the Redis-backed domain.StateCache.
type RedisStateCache struct {
	client redis.UniversalClient
}

var _ domain.StateCache = (*RedisStateCache)(nil)

// NewRedisStateCache builds the cache over client.
func NewRedisStateCache(client redis.UniversalClient) *RedisStateCache {
	return &RedisStateCache{client: client}
}

// Save stores state unless Redis already holds the same or a newer version.
func (c *RedisStateCache) Save(ctx context.Context, state domain.TenantState) (bool, error) {
	stored, err := saveScript.Run(ctx, c.client, []string{StatesKey}, state.TenantID, encode(state), state.Version).Int()
	if err != nil {
		return false, fmt.Errorf("usage: save state of %s: %w", state.TenantID, err)
	}
	return stored == 1, nil
}

// LoadAll returns every cached state. Unreadable entries are skipped: one
// corrupt field must not keep the control plane from starting.
func (c *RedisStateCache) LoadAll(ctx context.Context) ([]domain.TenantState, error) {
	fields, err := c.client.HGetAll(ctx, StatesKey).Result()
	if err != nil {
		return nil, fmt.Errorf("usage: load states: %w", err)
	}
	states := make([]domain.TenantState, 0, len(fields))
	for tenantID, value := range fields {
		state, err := decode(tenantID, value)
		if err != nil {
			continue
		}
		states = append(states, state)
	}
	return states, nil
}

func encode(state domain.TenantState) string {
	return strconv.FormatInt(state.Version, 10) + "|" + string(state.Status) + "|" + string(state.Reason)
}

func decode(tenantID, value string) (domain.TenantState, error) {
	parts := strings.SplitN(value, "|", 3)
	if len(parts) != 3 {
		return domain.TenantState{}, fmt.Errorf("usage: malformed state %q", value)
	}
	version, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return domain.TenantState{}, fmt.Errorf("usage: malformed version %q: %w", parts[0], err)
	}
	return domain.NewTenantState(tenantID, domain.Status(parts[1]), domain.Reason(parts[2]), version)
}
