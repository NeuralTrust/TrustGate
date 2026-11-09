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
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func newAgentSecurityPluginAll(t *testing.T, v2URL, agentSecurityURL string, gateways map[string]string) *Plugin {
	t.Helper()
	p := New(adapter.NewRegistry(), v2URL, testTimeout, "test-client", "test-secret", nil,
		withBaseTransport(testTransport(t)),
		WithAgentSecurity(AgentSecurityConfig{BaseURL: agentSecurityURL, Timeout: time.Second, ClientID: "agentSecurity-client", ClientSecret: "agentSecurity-secret", Gateways: gateways, ShadowAll: true}))
	t.Cleanup(p.agentSecurity.wait)
	return p
}

func runAgentSecurityOnce(t *testing.T, p *Plugin) {
	t.Helper()
	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil))
	require.NoError(t, err)
	p.agentSecurity.wait()
}

func TestAgentSecurityShadowAllRequestsTokenByGatewayOnly(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	agentSecurity := &fakeAgentSecurity{}
	p := newAgentSecurityPluginAll(t, newServer(t, v2).URL, newAgentSecurityServer(t, agentSecurity).URL, nil)

	runAgentSecurityOnce(t, p)
	runAgentSecurityOnce(t, p)

	requests, tokens, _ := agentSecurity.seen()
	assert.Len(t, requests, 2)
	require.Len(t, tokens, 1, "gateway-only token is cached")
	assert.Equal(t, "gw-test", tokens[0]["gateway_id"])
	assert.NotContains(t, tokens[0], "integration_id")
}

func TestAgentSecurityShadowAllExplicitMapWins(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	agentSecurity := &fakeAgentSecurity{}
	p := newAgentSecurityPluginAll(t, newServer(t, v2).URL, newAgentSecurityServer(t, agentSecurity).URL, map[string]string{"gw-test": testAgentSecurityIntegrationID})

	runAgentSecurityOnce(t, p)

	requests, tokens, _ := agentSecurity.seen()
	assert.Len(t, requests, 1)
	require.Len(t, tokens, 1)
	assert.Equal(t, testAgentSecurityIntegrationID, tokens[0]["integration_id"])
}

func TestAgentSecurityShadowAllTokenCacheSeparatesExplicitFromGatewayOnly(t *testing.T) {
	t.Parallel()
	gwOnly := tokenParams{baseURL: "http://x", gatewayID: "gw"}
	explicit := tokenParams{baseURL: "http://x", collectorID: testAgentSecurityIntegrationID, gatewayID: "gw"}
	assert.NotEqual(t, gwOnly.cacheKey(), explicit.cacheKey())
}

func TestAgentSecurityUnknownGatewaySkippedAndCached(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	agentSecurity := &fakeAgentSecurity{refuseStatus: http.StatusNotFound, refuseCode: "unknown_gateway"}
	p := newAgentSecurityPluginAll(t, newServer(t, v2).URL, newAgentSecurityServer(t, agentSecurity).URL, nil)

	for range 3 {
		runAgentSecurityOnce(t, p)
	}

	requests, tokens, _ := agentSecurity.seen()
	assert.Empty(t, requests)
	assert.Len(t, tokens, 1, "the refusal is cached, later requests do not ask")
	assert.Equal(t, 3, v2.count(), "TrustGuard is unaffected")
}

func TestAgentSecurityUnknownGatewayAskedAgainAfterTTL(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	agentSecurity := &fakeAgentSecurity{refuseStatus: http.StatusNotFound, refuseCode: "unknown_gateway"}
	p := newAgentSecurityPluginAll(t, newServer(t, v2).URL, newAgentSecurityServer(t, agentSecurity).URL, nil)
	clock := time.Now()
	p.agentSecurity.now = func() time.Time { return clock }

	runAgentSecurityOnce(t, p)
	clock = clock.Add(agentSecurityRefusedTTL + time.Second)
	runAgentSecurityOnce(t, p)

	_, tokens, _ := agentSecurity.seen()
	assert.Len(t, tokens, 2)
}

func TestAgentSecurityAmbiguousGatewaySkippedAndCached(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	agentSecurity := &fakeAgentSecurity{refuseStatus: http.StatusConflict, refuseCode: "ambiguous_gateway"}
	p := newAgentSecurityPluginAll(t, newServer(t, v2).URL, newAgentSecurityServer(t, agentSecurity).URL, nil)

	runAgentSecurityOnce(t, p)
	runAgentSecurityOnce(t, p)

	requests, tokens, _ := agentSecurity.seen()
	assert.Empty(t, requests)
	assert.Len(t, tokens, 1)
	assert.Equal(t, 2, v2.count())
}

func newRefusalSender(clock *time.Time) *agentSecuritySender {
	return &agentSecuritySender{now: func() time.Time { return *clock }, refused: map[string]refusal{}}
}

func TestAgentSecurityRefusedCacheEvictsEarliestAtCap(t *testing.T) {
	t.Parallel()
	clock := time.Now()
	s := newRefusalSender(&clock)
	for i := range agentSecurityRefusedMax {
		clock = clock.Add(time.Millisecond)
		assert.True(t, s.markRefused("gw-"+strconv.Itoa(i), codeUnknownGateway))
	}
	clock = clock.Add(time.Millisecond)
	assert.True(t, s.markRefused("new", codeAmbiguousGateway), "the new refusal is cached, not warned on every request")
	assert.Len(t, s.refused, agentSecurityRefusedMax)
	_, evicted := s.isRefused("gw-0")
	assert.False(t, evicted, "earliest expiry is evicted")
	code, ok := s.isRefused("new")
	assert.True(t, ok)
	assert.Equal(t, codeAmbiguousGateway, code)
	assert.False(t, s.markRefused("new", codeAmbiguousGateway), "second mark in the period is not new")
}

func TestAgentSecurityRefusedCacheSweepsExpiredAtCap(t *testing.T) {
	t.Parallel()
	clock := time.Now()
	s := newRefusalSender(&clock)
	for i := range agentSecurityRefusedMax {
		s.markRefused("gw-"+strconv.Itoa(i), codeUnknownGateway)
	}
	clock = clock.Add(agentSecurityRefusedTTL + time.Second)
	s.markRefused("fresh", codeUnknownGateway)
	assert.Len(t, s.refused, 1)
}

func TestAgentSecurityRefusedCacheParallel(t *testing.T) {
	t.Parallel()
	s := &agentSecuritySender{now: time.Now, refused: map[string]refusal{}}
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 500 {
				gw := "gw-" + strconv.Itoa((i*500+j)%64)
				s.markRefused(gw, codeUnknownGateway)
				s.isRefused(gw)
			}
		}()
	}
	wg.Wait()
	assert.LessOrEqual(t, len(s.refused), 64)
}

func TestAgentSecurityAmbiguousCachedOutcomeLabel(t *testing.T) {
	t.Parallel()
	clock := time.Now()
	s := newRefusalSender(&clock)
	s.markRefused("gw", codeAmbiguousGateway)
	code, ok := s.isRefused("gw")
	require.True(t, ok)
	assert.Equal(t, codeAmbiguousGateway, code, "cached hits report the matching outcome")
}

func TestAgentSecurityNotFoundTokenErrorIsNotCachedAsRefusal(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	agentSecurity := &fakeAgentSecurity{refuseStatus: http.StatusNotFound, refuseCode: "not_found"}
	p := newAgentSecurityPluginAll(t, newServer(t, v2).URL, newAgentSecurityServer(t, agentSecurity).URL, nil)

	runAgentSecurityOnce(t, p)
	assert.Empty(t, p.agentSecurity.refused)
	assert.True(t, p.agentSecurity.inTokenBackoff(), "a plain token failure pauses copies")
}

func TestAgentSecurityTokenFailureBacksOffThenRetries(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	agentSecurity := &fakeAgentSecurity{refuseStatus: http.StatusInternalServerError, refuseCode: "boom"}
	p := newAgentSecurityPluginAll(t, newServer(t, v2).URL, newAgentSecurityServer(t, agentSecurity).URL, nil)
	clock := time.Now()
	p.agentSecurity.now = func() time.Time { return clock }

	runAgentSecurityOnce(t, p)
	runAgentSecurityOnce(t, p)
	_, tokens, _ := agentSecurity.seen()
	assert.Len(t, tokens, 1, "no token request during the backoff")

	clock = clock.Add(agentSecurityTokenBackoff + time.Second)
	runAgentSecurityOnce(t, p)
	_, tokens, _ = agentSecurity.seen()
	assert.Len(t, tokens, 2)
}

func TestTokenStatusError(t *testing.T) {
	t.Parallel()
	body := func(code string) []byte { return []byte(`{"error":"` + code + `"}`) }
	tests := []struct {
		name    string
		status  int
		body    []byte
		refused string
		auth    bool
	}{
		{"404 unknown_gateway", 404, body("unknown_gateway"), "unknown_gateway", false},
		{"409 ambiguous_gateway", 409, body("ambiguous_gateway"), "ambiguous_gateway", false},
		{"404 other code", 404, body("not_found"), "", false},
		{"404 empty body", 404, nil, "", false},
		{"409 other code", 409, body("conflict"), "", false},
		{"409 wrong pairing", 409, body("unknown_gateway"), "", false},
		{"404 wrong pairing", 404, body("ambiguous_gateway"), "", false},
		{"400", 400, body("invalid_scope"), "", true},
		{"401", 401, body("invalid_client"), "", true},
		{"403", 403, nil, "", true},
		{"500", 500, nil, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tokenStatusError(tc.status, tc.body)
			var refused *gatewayRefusedError
			var auth *authRejectedError
			assert.Equal(t, tc.refused != "", errors.As(err, &refused))
			if tc.refused != "" {
				assert.Equal(t, tc.refused, refused.code)
				assert.Equal(t, failureReasonTransport, reasonOfError(context.Background(), err))
			}
			assert.Equal(t, tc.auth, errors.As(err, &auth))
		})
	}
}

func TestAgentSecurityShadowOffUnchanged(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	agentSecurity := &fakeAgentSecurity{}
	p := newAgentSecurityPlugin(t, newServer(t, v2).URL, newAgentSecurityServer(t, agentSecurity).URL, map[string]string{"gw-other": ""})

	runAgentSecurityOnce(t, p)

	requests, tokens, _ := agentSecurity.seen()
	assert.Empty(t, requests)
	assert.Empty(t, tokens)
}

func TestAgentSecurityShadowAllStillNeedsCredentials(t *testing.T) {
	t.Parallel()
	assert.False(t, AgentSecurityConfig{BaseURL: "http://x", ClientID: "id", ShadowAll: true}.enabled())
	assert.False(t, AgentSecurityConfig{ClientID: "id", ClientSecret: "s", ShadowAll: true}.enabled())
	assert.True(t, AgentSecurityConfig{BaseURL: "http://x", ClientID: "id", ClientSecret: "s", ShadowAll: true}.enabled())
}
