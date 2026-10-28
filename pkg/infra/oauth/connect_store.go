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

package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/redis/go-redis/v9"
)

const (
	ticketPrefix  = "oauth:connect:ticket:"
	connectPrefix = "oauth:connect:state:"
	finishPrefix  = "oauth:connect:finish:"
	// finishStatePrefix points from a flow to its one pending finish, so a
	// callback that arrives again for the same state replaces it.
	finishStatePrefix = "oauth:connect:finish-state:"
	clientPrefix      = "oauth:dcr:client:"
	ticketTTL         = appoauth.ConnectTicketTTL
	connectTTL        = appoauth.ConnectStateTTL
	finishTTL         = appoauth.ConnectFinishTTL
)

var (
	_ appoauth.ConnectStore = (*ConnectStore)(nil)
	_ appoauth.ClientStore  = (*ConnectStore)(nil)
)

type ConnectStore struct {
	rdb redis.UniversalClient
}

func NewConnectStore(rdb redis.UniversalClient) *ConnectStore {
	return &ConnectStore{rdb: rdb}
}

func (s *ConnectStore) SaveTicket(ctx context.Context, id string, t appoauth.ConnectTicket) error {
	return s.set(ctx, ticketPrefix+id, t, ticketTTL)
}

func (s *ConnectStore) GetTicket(ctx context.Context, id string) (*appoauth.ConnectTicket, error) {
	var t appoauth.ConnectTicket
	raw, err := s.rdb.Get(ctx, ticketPrefix+id).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("oauth connect store: get: %w", err)
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("oauth connect store: decode: %w", err)
	}
	return &t, nil
}

func (s *ConnectStore) SaveConnect(ctx context.Context, state string, c appoauth.ConnectState) error {
	return s.set(ctx, connectPrefix+state, c, connectTTL)
}

func (s *ConnectStore) TakeConnect(ctx context.Context, state string) (*appoauth.ConnectState, error) {
	raw, err := s.rdb.GetDel(ctx, connectPrefix+state).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("oauth connect store: getdel: %w", err)
	}
	var c appoauth.ConnectState
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("oauth connect store: decode: %w", err)
	}
	return &c, nil
}

// PeekConnect reads a started authorization without removing it.
func (s *ConnectStore) PeekConnect(ctx context.Context, state string) (*appoauth.ConnectState, error) {
	raw, err := s.rdb.Get(ctx, connectPrefix+state).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("oauth connect store: get: %w", err)
	}
	var c appoauth.ConnectState
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("oauth connect store: decode: %w", err)
	}
	return &c, nil
}

// SaveFinish keeps a provider callback for ConnectFinishTTL until the start
// origin finishes it. A flow has one pending finish at a time: saving
// another one with the same state removes the one before.
func (s *ConnectStore) SaveFinish(ctx context.Context, token string, f appoauth.ConnectFinish) error {
	if err := s.set(ctx, finishPrefix+token, f, finishTTL); err != nil {
		return err
	}
	stateKey := finishStatePrefix + finishStateID(f.State)
	previous, err := s.rdb.SetArgs(ctx, stateKey, token, redis.SetArgs{TTL: finishTTL, Get: true}).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("oauth connect store: set finish state: %w", err)
	}
	if previous != "" && previous != token {
		if err := s.rdb.Del(ctx, finishPrefix+previous).Err(); err != nil {
			return fmt.Errorf("oauth connect store: drop previous finish: %w", err)
		}
	}
	return nil
}

// finishStateID keys a flow's pending finish by a digest of its state, so the
// state itself is not written into a key name.
func finishStateID(state string) string {
	sum := sha256.Sum256([]byte(state))
	return hex.EncodeToString(sum[:])
}

// TakeFinish reads and removes a pending finish in one step (GETDEL), so a
// token is redeemed at most once.
func (s *ConnectStore) TakeFinish(ctx context.Context, token string) (*appoauth.ConnectFinish, error) {
	raw, err := s.rdb.GetDel(ctx, finishPrefix+token).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("oauth connect store: getdel finish: %w", err)
	}
	var f appoauth.ConnectFinish
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("oauth connect store: decode finish: %w", err)
	}
	return &f, nil
}

func (s *ConnectStore) SaveClient(ctx context.Context, key string, c appoauth.RegisteredClient) error {
	return s.set(ctx, clientPrefix+key, c, 0)
}

// SaveClientIfAbsent claims the registration slot atomically (SETNX), so that
// when several replicas register a dynamic client at the same moment exactly
// one client_id survives and every replica converges on it.
func (s *ConnectStore) SaveClientIfAbsent(ctx context.Context, key string, c appoauth.RegisteredClient) (*appoauth.RegisteredClient, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("oauth connect store: encode client: %w", err)
	}
	won, err := s.rdb.SetNX(ctx, clientPrefix+key, raw, 0).Result()
	if err != nil {
		return nil, fmt.Errorf("oauth connect store: claim client: %w", err)
	}
	if won {
		return &c, nil
	}
	incumbent, err := s.GetClient(ctx, key)
	if err != nil {
		return nil, err
	}
	if incumbent == nil {
		// The winner's entry vanished between SETNX and the read (eviction or an
		// explicit delete). Fall back to our own registration rather than
		// reporting no client at all.
		return &c, nil
	}
	return incumbent, nil
}

// replaceClientScript writes ARGV[2] only when the stored JSON client's
// client_id is ARGV[1]. Returns {1, written} or {0, previous}. Previous is
// empty when the slot is empty.
const replaceClientScript = `
local raw = redis.call('GET', KEYS[1])
if not raw or raw == '' then
  return {0, ''}
end
local ok, row = pcall(cjson.decode, raw)
if not ok or type(row) ~= 'table' or row['client_id'] ~= ARGV[1] then
  return {0, raw}
end
redis.call('SET', KEYS[1], ARGV[2])
return {1, ARGV[2]}
`

func (s *ConnectStore) ReplaceClientIfMatch(ctx context.Context, key, expectedClientID string, next appoauth.RegisteredClient) (*appoauth.RegisteredClient, bool, error) {
	rawNext, err := json.Marshal(next)
	if err != nil {
		return nil, false, fmt.Errorf("oauth connect store: encode client: %w", err)
	}
	res, err := s.rdb.Eval(ctx, replaceClientScript, []string{clientPrefix + key}, expectedClientID, string(rawNext)).Result()
	if err != nil {
		return nil, false, fmt.Errorf("oauth connect store: replace client: %w", err)
	}
	swapped, raw, err := replaceClientResult(res)
	if err != nil {
		return nil, false, err
	}
	if swapped {
		return &next, true, nil
	}
	if raw == "" {
		return nil, false, nil
	}
	var current appoauth.RegisteredClient
	if err := json.Unmarshal([]byte(raw), &current); err != nil {
		return nil, false, fmt.Errorf("oauth connect store: decode client: %w", err)
	}
	return &current, false, nil
}

func replaceClientResult(res any) (bool, string, error) {
	vals, ok := res.([]any)
	if !ok || len(vals) != 2 {
		return false, "", fmt.Errorf("oauth connect store: replace client: unexpected reply")
	}
	swapped, ok := redisFlag(vals[0])
	if !ok {
		return false, "", fmt.Errorf("oauth connect store: replace client: unexpected flag")
	}
	switch raw := vals[1].(type) {
	case string:
		return swapped, raw, nil
	case []byte:
		return swapped, string(raw), nil
	case nil:
		return swapped, "", nil
	default:
		return false, "", fmt.Errorf("oauth connect store: replace client: unexpected value")
	}
}

func redisFlag(v any) (bool, bool) {
	switch n := v.(type) {
	case int64:
		return n == 1, true
	case int:
		return n == 1, true
	default:
		return false, false
	}
}

// HasDynamicClient reports whether a dynamic client is cached for this
// gateway and catalog code. The key is gateway|provider, and provider is the
// code plus a resource fingerprint, so the match is the code and the code
// followed by "|", never a raw prefix of the code.
func (s *ConnectStore) HasDynamicClient(ctx context.Context, gatewayID ids.GatewayID, code string) (bool, error) {
	if s == nil || s.rdb == nil {
		return false, errors.New("oauth connect store: redis unavailable")
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return false, nil
	}
	gateway := gatewayID.String()
	exact := clientPrefix + gateway + "|" + code
	n, err := s.rdb.Exists(ctx, exact).Result()
	if err != nil {
		return false, fmt.Errorf("oauth connect store: dynamic client: %w", err)
	}
	if n > 0 {
		return true, nil
	}
	pattern := clientPrefix + escapeRedisGlob(gateway) + "|" + escapeRedisGlob(code) + "|*"
	found := false
	err = cache.ScanKeys(ctx, s.rdb, pattern, 100, func(_ context.Context, keys []string) error {
		for _, key := range keys {
			if dynamicClientForCode(key, gateway, code) {
				found = true
				return cache.ErrStopScan
			}
		}
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("oauth connect store: dynamic client: %w", err)
	}
	return found, nil
}

func dynamicClientForCode(key, gatewayID, code string) bool {
	rest, ok := strings.CutPrefix(key, clientPrefix)
	if !ok {
		return false
	}
	prefix := gatewayID + "|" + code
	return rest == prefix || strings.HasPrefix(rest, prefix+"|")
}

func escapeRedisGlob(value string) string {
	return strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`, `]`, `\]`).Replace(value)
}

func (s *ConnectStore) GetClient(ctx context.Context, key string) (*appoauth.RegisteredClient, error) {
	raw, err := s.rdb.Get(ctx, clientPrefix+key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("oauth connect store: get client: %w", err)
	}
	var c appoauth.RegisteredClient
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("oauth connect store: decode client: %w", err)
	}
	return &c, nil
}

func (s *ConnectStore) set(ctx context.Context, key string, v any, ttl time.Duration) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("oauth connect store: encode: %w", err)
	}
	if err := s.rdb.Set(ctx, key, raw, ttl).Err(); err != nil {
		return fmt.Errorf("oauth connect store: set: %w", err)
	}
	return nil
}
