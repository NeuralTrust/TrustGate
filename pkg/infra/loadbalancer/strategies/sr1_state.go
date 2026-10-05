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

package strategies

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// SR1Store atomically selects a committed rung and enforces the one-escape budget.
type SR1Store interface {
	Choose(ctx context.Context, key, turnID string, desired, rungs int, ttl time.Duration, newUser bool) (int, error)
}

// RedisSR1Store shares the cache-lifetime policy across gateway replicas.
type RedisSR1Store struct{ client *redis.Client }

// NewRedisSR1Store creates an atomic Redis-backed SR-1 state store.
func NewRedisSR1Store(client *redis.Client) *RedisSR1Store {
	return &RedisSR1Store{client: client}
}

var sr1Script = redis.NewScript(`
local desired, rungs, ttl = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3])
local new_user, turn_id = ARGV[4] == '1', ARGV[5]
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local rung = tonumber(redis.call('HGET', KEYS[1], 'rung'))
local escapes = tonumber(redis.call('HGET', KEYS[1], 'escapes'))
local last = tonumber(redis.call('HGET', KEYS[1], 'last'))
local turn = redis.call('HGET', KEYS[1], 'turn')
if not rung or not escapes or not last or rung ~= math.floor(rung) or escapes ~= math.floor(escapes) or rung < 0 or rung >= rungs or escapes < 0 or escapes > 1 or last > now or now - last > ttl then
    rung, escapes = desired, 0
elseif new_user and turn ~= turn_id and desired > rung and escapes < 1 then
    rung, escapes = math.min(rung + 1, rungs - 1), 1
end
if new_user then turn = turn_id end
redis.call('HSET', KEYS[1], 'rung', rung, 'escapes', escapes, 'last', now, 'turn', turn or '')
redis.call('PEXPIRE', KEYS[1], ttl + 1000)
return rung
`)

// Choose commits at cold points and permits one one-rung escape on a new user turn.
func (s *RedisSR1Store) Choose(ctx context.Context, key, turnID string, desired, rungs int, ttl time.Duration, newUser bool) (int, error) {
	if s == nil || s.client == nil {
		return 0, errors.New("SR-1 state store is unavailable")
	}
	if rungs < 2 || rungs > 3 || desired < 0 || desired >= rungs || ttl.Milliseconds() < 1 || turnID == "" {
		return 0, errors.New("invalid SR-1 state request")
	}
	user := "0"
	if newUser {
		user = "1"
	}
	rung, err := sr1Script.Run(ctx, s.client, []string{key}, desired, rungs, ttl.Milliseconds(), user, turnID).Int()
	if err != nil {
		return 0, fmt.Errorf("SR-1 state selection: %w", err)
	}
	if rung < 0 || rung >= rungs {
		return 0, errors.New("invalid stored SR-1 rung")
	}
	return rung, nil
}
