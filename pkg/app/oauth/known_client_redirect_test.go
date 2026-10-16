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
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func knownClientRedirectCounts(t *testing.T, reader sdkmetric.Reader) map[string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect metrics: %v", err)
	}
	counts := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != knownClientRedirectMetric {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s is not an int64 sum", knownClientRedirectMetric)
			}
			for _, dp := range sum.DataPoints {
				kind, _ := dp.Attributes.Value(attribute.Key("redirect_kind"))
				counts[kind.AsString()] += dp.Value
			}
		}
	}
	return counts
}

// Measuring only: every redirect_uri the upstream client_id path accepted
// before is still accepted, and each is counted by kind.
func TestAuthorizeCountsRedirectsOnUpstreamClientID(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	prev := otel.GetMeterProvider()
	otel.SetMeterProvider(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)))
	t.Cleanup(func() { otel.SetMeterProvider(prev) })

	idp, _ := fakeIdP(t)
	store := newMemFlowStore()
	_ = store.SaveGatewayClient(context.Background(), RegisteredGatewayClient{
		ClientID:     "agw-registered",
		RedirectURIs: []string{"https://registered.example/cb"},
	})
	proxy := newProxyUnderTest(t, idp.URL, store)

	for _, tc := range []struct{ clientID, redirectURI string }{
		{"gw-client-id", "https://client.example/cb"},
		{"gw-client-id", "https://localhost:8443/cb"},
		{"gw-client-id", "http://127.0.0.1:1234/callback"},
		{"gw-client-id", "cursor://anysphere.cursor-mcp/oauth/callback"},
		{"agw-registered", "https://registered.example/cb"},
	} {
		if _, err := authorizeLocation(proxy, context.Background(), "http://gw.example.com", AuthorizeRequest{
			ResponseType:        "code",
			ClientID:            tc.clientID,
			RedirectURI:         tc.redirectURI,
			CodeChallenge:       s256("v"),
			CodeChallengeMethod: "S256",
		}); err != nil {
			t.Fatalf("%s with %s must still be accepted: %v", tc.clientID, tc.redirectURI, err)
		}
	}

	got := knownClientRedirectCounts(t, reader)
	want := map[string]int64{redirectKindHTTPS: 1, redirectKindLoopback: 2, redirectKindPrivateUse: 1}
	if len(got) != len(want) {
		t.Fatalf("counts = %v, want %v (a registered client must not be counted)", got, want)
	}
	for kind, n := range want {
		if got[kind] != n {
			t.Fatalf("counts = %v, want %v", got, want)
		}
	}
}

func TestClassifyKnownClientRedirect(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ raw, kind, origin string }{
		{"https://claude.ai/api/mcp/auth_callback?x=1", redirectKindHTTPS, "https://claude.ai"},
		{"https://localhost:8443/cb", redirectKindLoopback, "https://localhost:8443"},
		{"https://[::1]/cb", redirectKindLoopback, "https://[::1]"},
		{"http://127.0.0.1:1234/callback", redirectKindLoopback, "http://127.0.0.1:1234"},
		{"cursor://anysphere.cursor-mcp/oauth/callback", redirectKindPrivateUse, "cursor://anysphere.cursor-mcp"},
	} {
		kind, origin := classifyKnownClientRedirect(tc.raw)
		if kind != tc.kind || origin != tc.origin {
			t.Errorf("classify(%q) = (%q, %q), want (%q, %q)", tc.raw, kind, origin, tc.kind, tc.origin)
		}
	}
}
