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

package trustguard

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
)

const (
	engineLookupTimeout = 3 * time.Second
	// A gateway TrustGuard v2 gave a token for stays v2 this long; one it does not know stays
	// v1 this long; any other answer is v1 for the short one, so a TrustGuard that is down is
	// not asked on every request.
	engineV2TTL    = 5 * time.Minute
	engineV1TTL    = 3 * time.Minute
	engineErrorTTL = 30 * time.Second
	engineCacheMax = 4096
)

var _ appplugins.GatewayEngines = (*EngineResolver)(nil)

type engineEntry struct {
	v2    bool
	until time.Time
}

// EngineResolver tells which TrustGuard engine a gateway is on by asking TrustGuard v2 for the
// gateway's platform token: a token means v2, unknown_gateway means v1. Anything else (an error,
// a timeout, no v2 credentials or base URL) is v1, so nothing changes until v2 is in use.
type EngineResolver struct {
	tokens  *tokenManager
	baseURL string
	now     func() time.Time

	mu    sync.Mutex
	cache map[string]engineEntry
}

// NewEngineResolver builds the resolver with the credentials of the v2 platform client.
func NewEngineResolver(baseURL, clientID, clientSecret string) *EngineResolver {
	httpClient := &http.Client{
		Timeout:   engineLookupTimeout,
		Transport: o11y.InternalTransportOver(http.DefaultTransport, peerService, v2EvaluateSpanName),
	}
	tokens := newTokenManager(httpClient, clientID, clientSecret)
	tokens.useV2()
	return newEngineResolver(strings.TrimSpace(baseURL), tokens)
}

func newEngineResolver(baseURL string, tokens *tokenManager) *EngineResolver {
	return &EngineResolver{tokens: tokens, baseURL: baseURL, now: time.Now, cache: make(map[string]engineEntry)}
}

// TrustGuardV2 reports whether gatewayID is on TrustGuard v2.
func (r *EngineResolver) TrustGuardV2(ctx context.Context, gatewayID string) bool {
	gatewayID = strings.TrimSpace(gatewayID)
	if r == nil || gatewayID == "" || r.baseURL == "" || !r.tokens.configured() {
		return false
	}
	if v2, ok := r.cached(gatewayID); ok {
		return v2
	}
	callCtx, cancel := context.WithTimeout(ctx, engineLookupTimeout)
	defer cancel()
	_, err := r.tokens.token(callCtx, tokenParams{baseURL: r.baseURL, gatewayID: gatewayID})
	var refused *gatewayRefusedError
	switch {
	case err == nil:
		r.store(gatewayID, true, engineV2TTL)
		return true
	case errors.As(err, &refused) && refused.code == codeUnknownGateway:
		r.store(gatewayID, false, engineV1TTL)
	case errors.Is(err, context.Canceled):
		// The caller left; that says nothing about the gateway.
	default:
		r.store(gatewayID, false, engineErrorTTL)
	}
	return false
}

func (r *EngineResolver) cached(gatewayID string) (v2, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, found := r.cache[gatewayID]
	if !found {
		return false, false
	}
	if !r.now().Before(e.until) {
		delete(r.cache, gatewayID)
		return false, false
	}
	return e.v2, true
}

func (r *EngineResolver) store(gatewayID string, v2 bool, ttl time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if _, exists := r.cache[gatewayID]; !exists && len(r.cache) >= engineCacheMax {
		for id, e := range r.cache {
			if !now.Before(e.until) {
				delete(r.cache, id)
			}
		}
		if len(r.cache) >= engineCacheMax {
			for id := range r.cache {
				delete(r.cache, id)
				break
			}
		}
	}
	r.cache[gatewayID] = engineEntry{v2: v2, until: now.Add(ttl)}
}
