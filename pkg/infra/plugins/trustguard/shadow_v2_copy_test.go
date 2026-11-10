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

func newV2ShadowPluginAll(t *testing.T, v2URL, v2ShadowURL string, gateways map[string]string) *Plugin {
	t.Helper()
	p := New(adapter.NewRegistry(), v2URL, testTimeout, "test-client", "test-secret", nil,
		withBaseTransport(testTransport(t)),
		WithV2Shadow(V2ShadowConfig{BaseURL: v2ShadowURL, Timeout: time.Second, ClientID: "v2Shadow-client", ClientSecret: "v2Shadow-secret", Gateways: gateways, ShadowAll: true}))
	t.Cleanup(p.v2Shadow.wait)
	return p
}

func runV2ShadowOnce(t *testing.T, p *Plugin) {
	t.Helper()
	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil))
	require.NoError(t, err)
	p.v2Shadow.wait()
}

func TestV2ShadowAllRequestsTokenByGatewayOnly(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	v2Shadow := &fakeV2Shadow{}
	p := newV2ShadowPluginAll(t, newServer(t, v2).URL, newV2ShadowServer(t, v2Shadow).URL, nil)

	runV2ShadowOnce(t, p)
	runV2ShadowOnce(t, p)

	requests, tokens, _ := v2Shadow.seen()
	assert.Len(t, requests, 2)
	require.Len(t, tokens, 1, "gateway-only token is cached")
	assert.Equal(t, "gw-test", tokens[0]["gateway_id"])
	assert.NotContains(t, tokens[0], "integration_id")
}

func TestV2ShadowAllExplicitMapWins(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	v2Shadow := &fakeV2Shadow{}
	p := newV2ShadowPluginAll(t, newServer(t, v2).URL, newV2ShadowServer(t, v2Shadow).URL, map[string]string{"gw-test": testV2ShadowIntegrationID})

	runV2ShadowOnce(t, p)

	requests, tokens, _ := v2Shadow.seen()
	assert.Len(t, requests, 1)
	require.Len(t, tokens, 1)
	assert.Equal(t, testV2ShadowIntegrationID, tokens[0]["integration_id"])
}

func TestV2ShadowAllTokenCacheSeparatesExplicitFromGatewayOnly(t *testing.T) {
	t.Parallel()
	gwOnly := tokenParams{baseURL: "http://x", gatewayID: "gw"}
	explicit := tokenParams{baseURL: "http://x", collectorID: testV2ShadowIntegrationID, gatewayID: "gw"}
	assert.NotEqual(t, gwOnly.cacheKey(), explicit.cacheKey())
}

func TestV2ShadowUnknownGatewaySkippedAndCached(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	v2Shadow := &fakeV2Shadow{refuseStatus: http.StatusNotFound, refuseCode: "unknown_gateway"}
	p := newV2ShadowPluginAll(t, newServer(t, v2).URL, newV2ShadowServer(t, v2Shadow).URL, nil)

	for range 3 {
		runV2ShadowOnce(t, p)
	}

	requests, tokens, _ := v2Shadow.seen()
	assert.Empty(t, requests)
	assert.Len(t, tokens, 1, "the refusal is cached, later requests do not ask")
	assert.Equal(t, 3, v2.count(), "TrustGuard is unaffected")
}

func TestV2ShadowUnknownGatewayAskedAgainAfterTTL(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	v2Shadow := &fakeV2Shadow{refuseStatus: http.StatusNotFound, refuseCode: "unknown_gateway"}
	p := newV2ShadowPluginAll(t, newServer(t, v2).URL, newV2ShadowServer(t, v2Shadow).URL, nil)
	clock := time.Now()
	p.v2Shadow.now = func() time.Time { return clock }

	runV2ShadowOnce(t, p)
	clock = clock.Add(v2ShadowRefusedTTL + time.Second)
	runV2ShadowOnce(t, p)

	_, tokens, _ := v2Shadow.seen()
	assert.Len(t, tokens, 2)
}

func TestV2ShadowAmbiguousGatewaySkippedAndCached(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	v2Shadow := &fakeV2Shadow{refuseStatus: http.StatusConflict, refuseCode: "ambiguous_gateway"}
	p := newV2ShadowPluginAll(t, newServer(t, v2).URL, newV2ShadowServer(t, v2Shadow).URL, nil)

	runV2ShadowOnce(t, p)
	runV2ShadowOnce(t, p)

	requests, tokens, _ := v2Shadow.seen()
	assert.Empty(t, requests)
	assert.Len(t, tokens, 1)
	assert.Equal(t, 2, v2.count())
}

func newRefusalSender(clock *time.Time) *v2ShadowSender {
	return &v2ShadowSender{now: func() time.Time { return *clock }, refused: map[string]refusal{}}
}

func TestV2ShadowRefusedCacheEvictsEarliestAtCap(t *testing.T) {
	t.Parallel()
	clock := time.Now()
	s := newRefusalSender(&clock)
	for i := range v2ShadowRefusedMax {
		clock = clock.Add(time.Millisecond)
		assert.True(t, s.markRefused("gw-"+strconv.Itoa(i), codeUnknownGateway))
	}
	clock = clock.Add(time.Millisecond)
	assert.True(t, s.markRefused("new", codeAmbiguousGateway), "the new refusal is cached, not warned on every request")
	assert.Len(t, s.refused, v2ShadowRefusedMax)
	_, evicted := s.isRefused("gw-0")
	assert.False(t, evicted, "earliest expiry is evicted")
	code, ok := s.isRefused("new")
	assert.True(t, ok)
	assert.Equal(t, codeAmbiguousGateway, code)
	assert.False(t, s.markRefused("new", codeAmbiguousGateway), "second mark in the period is not new")
}

func TestV2ShadowRefusedCacheSweepsExpiredAtCap(t *testing.T) {
	t.Parallel()
	clock := time.Now()
	s := newRefusalSender(&clock)
	for i := range v2ShadowRefusedMax {
		s.markRefused("gw-"+strconv.Itoa(i), codeUnknownGateway)
	}
	clock = clock.Add(v2ShadowRefusedTTL + time.Second)
	s.markRefused("fresh", codeUnknownGateway)
	assert.Len(t, s.refused, 1)
}

func TestV2ShadowRefusedCacheParallel(t *testing.T) {
	t.Parallel()
	s := &v2ShadowSender{now: time.Now, refused: map[string]refusal{}}
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

func TestV2ShadowAmbiguousCachedOutcomeLabel(t *testing.T) {
	t.Parallel()
	clock := time.Now()
	s := newRefusalSender(&clock)
	s.markRefused("gw", codeAmbiguousGateway)
	code, ok := s.isRefused("gw")
	require.True(t, ok)
	assert.Equal(t, codeAmbiguousGateway, code, "cached hits report the matching outcome")
}

func TestV2ShadowNotFoundTokenErrorIsNotCachedAsRefusal(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	v2Shadow := &fakeV2Shadow{refuseStatus: http.StatusNotFound, refuseCode: "not_found"}
	p := newV2ShadowPluginAll(t, newServer(t, v2).URL, newV2ShadowServer(t, v2Shadow).URL, nil)

	runV2ShadowOnce(t, p)
	assert.Empty(t, p.v2Shadow.refused)
	assert.True(t, p.v2Shadow.inTokenBackoff(), "a plain token failure pauses copies")
}

func TestV2ShadowTokenFailureBacksOffThenRetries(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	v2Shadow := &fakeV2Shadow{refuseStatus: http.StatusInternalServerError, refuseCode: "boom"}
	p := newV2ShadowPluginAll(t, newServer(t, v2).URL, newV2ShadowServer(t, v2Shadow).URL, nil)
	clock := time.Now()
	p.v2Shadow.now = func() time.Time { return clock }

	runV2ShadowOnce(t, p)
	runV2ShadowOnce(t, p)
	_, tokens, _ := v2Shadow.seen()
	assert.Len(t, tokens, 1, "no token request during the backoff")

	clock = clock.Add(v2ShadowTokenBackoff + time.Second)
	runV2ShadowOnce(t, p)
	_, tokens, _ = v2Shadow.seen()
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

func TestV2ShadowOffUnchanged(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	v2Shadow := &fakeV2Shadow{}
	p := newV2ShadowPlugin(t, newServer(t, v2).URL, newV2ShadowServer(t, v2Shadow).URL, map[string]string{"gw-other": ""})

	runV2ShadowOnce(t, p)

	requests, tokens, _ := v2Shadow.seen()
	assert.Empty(t, requests)
	assert.Empty(t, tokens)
}

func TestV2ShadowAllStillNeedsCredentials(t *testing.T) {
	t.Parallel()
	assert.False(t, V2ShadowConfig{BaseURL: "http://x", ClientID: "id", ShadowAll: true}.enabled())
	assert.False(t, V2ShadowConfig{ClientID: "id", ClientSecret: "s", ShadowAll: true}.enabled())
	assert.True(t, V2ShadowConfig{BaseURL: "http://x", ClientID: "id", ClientSecret: "s", ShadowAll: true}.enabled())
}
