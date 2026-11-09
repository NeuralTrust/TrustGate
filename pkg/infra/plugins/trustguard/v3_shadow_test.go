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
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func newV3PluginAll(t *testing.T, v2URL, v3URL string, gateways map[string]string) *Plugin {
	t.Helper()
	p := New(adapter.NewRegistry(), v2URL, testTimeout, "test-client", "test-secret", nil,
		withBaseTransport(testTransport(t)),
		WithV3(V3Config{BaseURL: v3URL, Timeout: time.Second, ClientID: "v3-client", ClientSecret: "v3-secret", Gateways: gateways, ShadowAll: true}))
	t.Cleanup(p.v3.wait)
	return p
}

func runV3Once(t *testing.T, p *Plugin) {
	t.Helper()
	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil))
	require.NoError(t, err)
	p.v3.wait()
}

func TestV3ShadowAllRequestsTokenByGatewayOnly(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	v3 := &fakeV3{}
	p := newV3PluginAll(t, newServer(t, v2).URL, newV3Server(t, v3).URL, nil)

	runV3Once(t, p)
	runV3Once(t, p)

	requests, tokens, _ := v3.seen()
	assert.Len(t, requests, 2)
	require.Len(t, tokens, 1, "gateway-only token is cached")
	assert.Equal(t, "gw-test", tokens[0]["gateway_id"])
	assert.NotContains(t, tokens[0], "integration_id")
}

func TestV3ShadowAllExplicitMapWins(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	v3 := &fakeV3{}
	p := newV3PluginAll(t, newServer(t, v2).URL, newV3Server(t, v3).URL, map[string]string{"gw-test": testV3IntegrationID})

	runV3Once(t, p)

	requests, tokens, _ := v3.seen()
	assert.Len(t, requests, 1)
	require.Len(t, tokens, 1)
	assert.Equal(t, testV3IntegrationID, tokens[0]["integration_id"])
}

func TestV3ShadowAllTokenCacheSeparatesExplicitFromGatewayOnly(t *testing.T) {
	t.Parallel()
	gwOnly := tokenParams{baseURL: "http://x", gatewayID: "gw"}
	explicit := tokenParams{baseURL: "http://x", collectorID: testV3IntegrationID, gatewayID: "gw"}
	assert.NotEqual(t, gwOnly.cacheKey(), explicit.cacheKey())
}

func TestV3UnknownGatewaySkippedAndCached(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	v3 := &fakeV3{refuseStatus: http.StatusNotFound, refuseCode: "unknown_gateway"}
	p := newV3PluginAll(t, newServer(t, v2).URL, newV3Server(t, v3).URL, nil)

	for range 3 {
		runV3Once(t, p)
	}

	requests, tokens, _ := v3.seen()
	assert.Empty(t, requests)
	assert.Len(t, tokens, 1, "the refusal is cached, later requests do not ask")
	assert.Equal(t, 3, v2.count(), "TrustGuard is unaffected")
}

func TestV3UnknownGatewayAskedAgainAfterTTL(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	v3 := &fakeV3{refuseStatus: http.StatusNotFound, refuseCode: "unknown_gateway"}
	p := newV3PluginAll(t, newServer(t, v2).URL, newV3Server(t, v3).URL, nil)
	clock := time.Now()
	p.v3.now = func() time.Time { return clock }

	runV3Once(t, p)
	clock = clock.Add(v3RefusedTTL + time.Second)
	runV3Once(t, p)

	_, tokens, _ := v3.seen()
	assert.Len(t, tokens, 2)
}

func TestV3AmbiguousGatewaySkippedAndCached(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	v3 := &fakeV3{refuseStatus: http.StatusConflict, refuseCode: "ambiguous_gateway"}
	p := newV3PluginAll(t, newServer(t, v2).URL, newV3Server(t, v3).URL, nil)

	runV3Once(t, p)
	runV3Once(t, p)

	requests, tokens, _ := v3.seen()
	assert.Empty(t, requests)
	assert.Len(t, tokens, 1)
	assert.Equal(t, 2, v2.count())
}

func TestV3RefusedCacheIsBounded(t *testing.T) {
	t.Parallel()
	s := &v3Sender{now: time.Now, refused: map[string]time.Time{}}
	for i := range v3RefusedMax + 100 {
		s.markRefused("gw-" + strconv.Itoa(i))
	}
	assert.LessOrEqual(t, len(s.refused), v3RefusedMax)
	assert.False(t, s.isRefused("gw-"+strconv.Itoa(v3RefusedMax+50)), "past the cap a gateway is not cached")
}

func TestV3ShadowOffUnchanged(t *testing.T) {
	t.Parallel()
	v2 := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	v3 := &fakeV3{}
	p := newV3Plugin(t, newServer(t, v2).URL, newV3Server(t, v3).URL, map[string]string{"gw-other": ""})

	runV3Once(t, p)

	requests, tokens, _ := v3.seen()
	assert.Empty(t, requests)
	assert.Empty(t, tokens)
}

func TestV3ShadowAllStillNeedsCredentials(t *testing.T) {
	t.Parallel()
	assert.False(t, V3Config{BaseURL: "http://x", ClientID: "id", ShadowAll: true}.enabled())
	assert.False(t, V3Config{ClientID: "id", ClientSecret: "s", ShadowAll: true}.enabled())
	assert.True(t, V3Config{BaseURL: "http://x", ClientID: "id", ClientSecret: "s", ShadowAll: true}.enabled())
}
