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
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/redis/go-redis/v9"
)

const (
	// The subject is wrapped in a hash tag so a tenant's quota, burst and
	// carried-over keys always live in one Redis Cluster slot. The sync script
	// touches several of them in a single call, which a cluster only allows
	// when they share a slot.
	quotaKeyPattern = "gt:rl:quota:{%s}:%s"
	burstKeyPattern = "gt:rl:burst:{%s}:%s"
	tokenKeyPattern = "gt:rl:tok:{%s}:%s" // #nosec G101 -- redis key format string, not a credential

	burstTTL = 2 * time.Minute

	// minQuotaTTL keeps a late delta for a month that has just ended from
	// creating a key that expires in the same instant.
	minQuotaTTL = time.Minute
)

// syncScript applies every bump of one tenant in a single atomic call and
// returns the new totals, in order.
//
// KEYS holds one key per bump, then the token key. ARGV is the number of bumps,
// the token TTL in milliseconds (0 for no token), then a delta and a TTL for each
// bump.
//
// The token makes a retry harmless. A sync whose reply was lost (a timeout, a
// cancelled call) may or may not have been applied, and the sender cannot tell,
// so it sends the same bumps again under the same token. The first thing the
// script does is claim the token with SET NX: when that fails the bumps were
// already applied, so the script skips them and only reports the totals. It also
// pushes the token's expiry out by the full TTL again: a round resent in several
// chunks reaches its later chunks late, and a token claimed once and never
// refreshed could expire between two sends of the same entry, so the next one
// would apply the bumps a second time.
//
// A bump with a zero delta is a plain read, so a tenant that spent nothing on
// this tick still learns what the others spent, and a quiet pod does not create
// keys. The TTL is set whenever a key has none rather than only on the first
// write: a key that lost its TTL for any reason would otherwise live forever.
var syncScript = redis.NewScript(`
local n = tonumber(ARGV[1])
local tokenTTL = tonumber(ARGV[2])
local apply = true
if tokenTTL > 0 then
  apply = redis.call("SET", KEYS[n + 1], "1", "NX", "PX", tokenTTL) ~= false
  if not apply then
    redis.call("PEXPIRE", KEYS[n + 1], tokenTTL)
  end
end
local totals = {}
for i = 1, n do
  local delta = tonumber(ARGV[i * 2 + 1])
  local ttl = tonumber(ARGV[i * 2 + 2])
  if apply and delta > 0 then
    totals[i] = redis.call("INCRBY", KEYS[i], delta)
    if redis.call("PTTL", KEYS[i]) < 0 then
      redis.call("PEXPIRE", KEYS[i], ttl)
    end
  else
    totals[i] = tonumber(redis.call("GET", KEYS[i]) or "0")
  end
end
return totals
`)

// Store keeps the shared plan counters in Redis. It is used only by the
// background sync, through its own client with short timeouts and no retries,
// so a slow or unreachable Redis costs the sync loop time and costs requests
// nothing.
type Store struct {
	redis  *redis.Client
	logger *slog.Logger
	now    func() time.Time
	loaded atomic.Bool
	// tokenTTL is how long a sync token is remembered. It must outlive the
	// last resend of a retained round (see domain.TokenTTL).
	tokenTTL time.Duration
}

// StoreOption tunes a Store.
type StoreOption func(*Store)

// WithFailedRetention sets the token TTL from the retention of failed rounds.
func WithFailedRetention(retention time.Duration) StoreOption {
	return func(s *Store) { s.tokenTTL = domain.TokenTTL(retention) }
}

// NewStore wraps the sync client. A nil client is a store that always fails,
// which the meter treats as Redis being down.
func NewStore(rc *redis.Client, logger *slog.Logger, opts ...StoreOption) *Store {
	s := &Store{redis: rc, logger: logger, now: time.Now, tokenTTL: domain.TokenTTL(0)}
	for _, o := range opts {
		o(s)
	}
	return s
}

func (s *Store) available() bool { return s != nil && s.redis != nil }

// Sync applies one batch, one pipelined round trip with one script call per
// tenant. go-redis does not fall back to EVAL when a script is missing from a
// pipelined EVALSHA, so the script is loaded up front and again, once, if Redis
// answers NOSCRIPT, which is what a restart or failover of Redis looks like.
func (s *Store) Sync(ctx context.Context, items []domain.SyncItem) ([]domain.SyncResult, error) {
	if !s.available() {
		return nil, errors.New("redis unavailable")
	}
	if len(items) == 0 {
		return nil, nil
	}
	if !s.loaded.Load() {
		if err := s.loadScript(ctx); err != nil {
			return nil, err
		}
	}

	results := s.pipeline(ctx, items)
	var retry []int
	for i, r := range results {
		if r.Err != nil && isNoScript(r.Err) {
			retry = append(retry, i)
		}
	}
	if len(retry) == 0 {
		return results, nil
	}

	s.loaded.Store(false)
	if err := s.loadScript(ctx); err != nil {
		return nil, err
	}
	again := make([]domain.SyncItem, len(retry))
	for j, i := range retry {
		again[j] = items[i]
	}
	for j, r := range s.pipeline(ctx, again) {
		results[retry[j]] = r
	}
	return results, nil
}

func (s *Store) loadScript(ctx context.Context) error {
	if err := syncScript.Load(ctx, s.redis).Err(); err != nil {
		return fmt.Errorf("load rate-limit sync script: %w", err)
	}
	s.loaded.Store(true)
	return nil
}

func (s *Store) pipeline(ctx context.Context, items []domain.SyncItem) []domain.SyncResult {
	results := make([]domain.SyncResult, len(items))
	pipe := s.redis.Pipeline()
	cmds := make([]*redis.Cmd, len(items))
	for i, item := range items {
		keys, args, err := s.keysAndArgs(item)
		if err != nil {
			results[i].Err = err
			continue
		}
		cmds[i] = pipe.EvalSha(ctx, syncScript.Hash(), keys, args...)
	}
	// Exec reports the first command error, which every command's own result
	// already carries; the per-item results are what the caller needs.
	_, _ = pipe.Exec(ctx)

	for i, cmd := range cmds {
		if cmd == nil {
			continue
		}
		raw, err := cmd.Slice()
		if err != nil {
			results[i].Err = err
			continue
		}
		totals := make([]int64, len(raw))
		for j, v := range raw {
			n, ok := v.(int64)
			if !ok {
				results[i].Err = fmt.Errorf("unexpected sync script reply %T", v)
				totals = nil
				break
			}
			totals[j] = n
		}
		results[i].Totals = totals
	}
	return results
}

func (s *Store) keysAndArgs(item domain.SyncItem) ([]string, []any, error) {
	keys := make([]string, 0, len(item.Bumps)+1)
	args := make([]any, 0, 2+2*len(item.Bumps))
	args = append(args, len(item.Bumps), int64(0))
	for _, b := range item.Bumps {
		key, ttl, err := s.keyFor(item.Subject, b)
		if err != nil {
			return nil, nil, err
		}
		keys = append(keys, key)
		args = append(args, b.Delta, ttl.Milliseconds())
	}
	// The token key shares the subject's hash tag, so it sits in the same slot
	// as the counters and the script stays single-slot on a cluster.
	tokenKey := fmt.Sprintf(tokenKeyPattern, subjectTag(item.Subject), item.Token)
	if item.Token != "" {
		args[1] = s.tokenTTL.Milliseconds()
	} else {
		tokenKey = fmt.Sprintf(tokenKeyPattern, subjectTag(item.Subject), "none")
	}
	keys = append(keys, tokenKey)
	return keys, args, nil
}

func (s *Store) keyFor(subject string, b domain.Bump) (string, time.Duration, error) {
	tag := subjectTag(subject)
	switch b.Kind {
	case domain.KindQuota:
		ttl, err := s.quotaTTL(b.Window)
		if err != nil {
			return "", 0, err
		}
		return fmt.Sprintf(quotaKeyPattern, tag, b.Window), ttl, nil
	case domain.KindBurst:
		return fmt.Sprintf(burstKeyPattern, tag, b.Window), burstTTL, nil
	default:
		return "", 0, fmt.Errorf("unknown counter kind %q", b.Kind)
	}
}

// quotaTTL expires a month's key when the month ends.
func (s *Store) quotaTTL(window string) (time.Duration, error) {
	month, err := time.Parse("2006-01", window)
	if err != nil {
		return 0, fmt.Errorf("invalid quota window %q: %w", window, err)
	}
	ttl := month.AddDate(0, 1, 0).Sub(s.now())
	if ttl < minQuotaTTL {
		ttl = minQuotaTTL
	}
	return ttl, nil
}

// subjectTag makes a subject safe to sit inside a hash tag: Redis takes the
// text between the first "{" and the next "}", so a brace in the subject would
// cut the tag short.
func subjectTag(subject string) string {
	return strings.NewReplacer("{", "_", "}", "_").Replace(subject)
}

func isNoScript(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "NOSCRIPT")
}
