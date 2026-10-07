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
	Read(ctx context.Context, key string, rungs int, ttl time.Duration) (int, error)
	Probe(ctx context.Context, key, turnID string, rungs int, ttl time.Duration, newUser, escapeEnabled bool) (SR1StateDecision, error)
	Choose(ctx context.Context, key, turnID string, desired, rungs int, ttl time.Duration, newUser, escapeEnabled bool) (int, error)
}

// SR1StateDecision indicates whether shared state needs a fresh difficulty score.
type SR1StateDecision struct {
	Rung       int
	NeedsScore bool
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
local escape_enabled, operation = ARGV[6] == '1', ARGV[7]
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local stored = redis.call('EXISTS', KEYS[1]) == 1
local rung = tonumber(redis.call('HGET', KEYS[1], 'rung'))
local escapes = tonumber(redis.call('HGET', KEYS[1], 'escapes'))
local last = tonumber(redis.call('HGET', KEYS[1], 'last'))
local turn = redis.call('HGET', KEYS[1], 'turn')
if stored and (not rung or not escapes or not last or not turn or rung ~= math.floor(rung) or escapes ~= math.floor(escapes) or rung < 0 or rung >= rungs or escapes < 0 or escapes > 1 or last < 0 or last > now) then
    return redis.error_reply('invalid SR-1 state')
end
local cold = not stored or now - last > ttl
if operation == 'read' then
    return {cold and -1 or rung, 0}
end
if operation == 'probe' then
    if cold then return {-1, 1} end
    local needs_score = escape_enabled and new_user and turn ~= turn_id and escapes < 1 and rung < rungs - 1
    redis.call('HSET', KEYS[1], 'last', now)
    redis.call('PEXPIRE', KEYS[1], ttl + 1000)
    return {rung, needs_score and 1 or 0}
end
if cold then
    rung, escapes = desired, 0
elseif escape_enabled and new_user and turn ~= turn_id and desired > rung and escapes < 1 then
    rung, escapes = math.min(rung + 1, rungs - 1), 1
end
if new_user then turn = turn_id end
redis.call('HSET', KEYS[1], 'rung', rung, 'escapes', escapes, 'last', now, 'turn', turn or '')
redis.call('PEXPIRE', KEYS[1], ttl + 1000)
return {rung, 0}
`)

// Read returns the active commitment without creating or touching session state.
func (s *RedisSR1Store) Read(ctx context.Context, key string, rungs int, ttl time.Duration) (int, error) {
	decision, err := s.run(ctx, key, "", -1, rungs, ttl, false, false, "read")
	return decision.Rung, err
}

// Probe atomically touches warm state and skips scoring when no decision can change.
func (s *RedisSR1Store) Probe(ctx context.Context, key, turnID string, rungs int, ttl time.Duration, newUser, escapeEnabled bool) (SR1StateDecision, error) {
	return s.run(ctx, key, turnID, -1, rungs, ttl, newUser, escapeEnabled, "probe")
}

// Choose commits cold decisions and enforces the optional one-rung escape atomically.
func (s *RedisSR1Store) Choose(ctx context.Context, key, turnID string, desired, rungs int, ttl time.Duration, newUser, escapeEnabled bool) (int, error) {
	decision, err := s.run(ctx, key, turnID, desired, rungs, ttl, newUser, escapeEnabled, "choose")
	return decision.Rung, err
}

func (s *RedisSR1Store) run(ctx context.Context, key, turnID string, desired, rungs int, ttl time.Duration, newUser, escapeEnabled bool, operation string) (SR1StateDecision, error) {
	if s == nil || s.client == nil {
		return SR1StateDecision{}, errors.New("SR-1 state store is unavailable")
	}
	nonCommit := operation == "probe" || operation == "read"
	if rungs < 2 || rungs > 3 || desired >= rungs || (desired < 0 && !nonCommit) || ttl.Milliseconds() < 1 || (turnID == "" && operation != "read") || key == "" {
		return SR1StateDecision{}, errors.New("invalid SR-1 state request")
	}
	user := "0"
	if newUser {
		user = "1"
	}
	escape := "0"
	if escapeEnabled {
		escape = "1"
	}
	result, err := sr1Script.Run(ctx, s.client, []string{key}, desired, rungs, ttl.Milliseconds(), user, turnID, escape, operation).Int64Slice()
	if err != nil {
		return SR1StateDecision{}, fmt.Errorf("SR-1 state selection: %w", err)
	}
	if len(result) != 2 || result[0] < -1 || result[0] >= int64(rungs) || (result[0] == -1 && !nonCommit) || result[1] < 0 || result[1] > 1 || (operation != "probe" && result[1] != 0) {
		return SR1StateDecision{}, errors.New("invalid stored SR-1 decision")
	}
	return SR1StateDecision{Rung: int(result[0]), NeedsScore: result[1] == 1}, nil
}
