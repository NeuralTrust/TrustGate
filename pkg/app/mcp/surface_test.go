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

package mcp

import (
	"context"
	"testing"
	"time"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
)

var toolsSince = time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)

func gatewayWithTools(on bool) *gatewaydomain.Gateway {
	gw := &gatewaydomain.Gateway{}
	if on {
		gw.Metadata = map[string]string{gatewaydomain.MetadataMCPGatewayToolsSinceKey: toolsSince.Format(time.RFC3339)}
	}
	return gw
}

func gatewaySession(connected time.Time) *identity.Principal {
	claims := map[string]any{identity.ClaimTokenUse: identity.TokenUseMCPSession}
	if !connected.IsZero() {
		// A verified JWT's numbers decode as float64.
		claims[identity.ClaimMCPSessionStart] = float64(connected.Unix())
	}
	return &identity.Principal{Subject: "user-1", Method: identity.MethodOAuth, Claims: claims}
}

func surfaceContext(gw *gatewaydomain.Gateway, principal *identity.Principal) context.Context {
	ctx := context.Background()
	if gw != nil {
		ctx = appgateway.WithGateway(ctx, gw)
	}
	if principal != nil {
		ctx = identity.WithPrincipal(ctx, principal)
	}
	return ctx
}

func TestSurfaceFor(t *testing.T) {
	t.Parallel()
	for label, tc := range map[string]struct {
		gw        *gatewaydomain.Gateway
		principal *identity.Principal
		want      Surface
	}{
		// Nothing changes for anyone until a gateway turns the tools on.
		"no gateway on the request":         {gw: nil, principal: gatewaySession(toolsSince.Add(time.Hour)), want: SurfaceLegacy},
		"tools off, new session":            {gw: gatewayWithTools(false), principal: gatewaySession(toolsSince.Add(time.Hour)), want: SurfaceLegacy},
		"tools off, api key":                {gw: gatewayWithTools(false), principal: &identity.Principal{Method: identity.MethodAPIKey}, want: SurfaceLegacy},
		"tools on, connected after":         {gw: gatewayWithTools(true), principal: gatewaySession(toolsSince.Add(time.Minute)), want: SurfaceConsolidated},
		"tools on, connected at the switch": {gw: gatewayWithTools(true), principal: gatewaySession(toolsSince), want: SurfaceConsolidated},
		// A hosted connector keeps the list it fetched when it connected.
		"tools on, connected before":              {gw: gatewayWithTools(true), principal: gatewaySession(toolsSince.Add(-time.Minute)), want: SurfaceLegacy},
		"tools on, session from before the claim": {gw: gatewayWithTools(true), principal: gatewaySession(time.Time{}), want: SurfaceLegacy},
		// Credentials with no connection time re-list on start.
		"tools on, api key":        {gw: gatewayWithTools(true), principal: &identity.Principal{Method: identity.MethodAPIKey}, want: SurfaceConsolidated},
		"tools on, personal key":   {gw: gatewayWithTools(true), principal: &identity.Principal{Method: identity.MethodPersonalKey}, want: SurfaceConsolidated},
		"tools on, external token": {gw: gatewayWithTools(true), principal: &identity.Principal{Method: identity.MethodExternalJWT, Claims: map[string]any{identity.ClaimMCPSessionStart: float64(1)}}, want: SurfaceConsolidated},
		"tools on, no principal":   {gw: gatewayWithTools(true), principal: nil, want: SurfaceConsolidated},
	} {
		if got := SurfaceFor(surfaceContext(tc.gw, tc.principal)); got != tc.want {
			t.Fatalf("%s: SurfaceFor = %s, want %s", label, got, tc.want)
		}
	}
}

// An OAuth token that is not one of the gateway's own sessions cannot claim a
// connection time: a customer identity provider writes its own claims.
func TestMCPSessionStart_OnlyForGatewaySessions(t *testing.T) {
	t.Parallel()
	foreign := &identity.Principal{Method: identity.MethodOAuth, Claims: map[string]any{
		identity.ClaimMCPSessionStart: float64(toolsSince.Unix()),
	}}
	if _, ok := foreign.MCPSessionStart(); ok {
		t.Fatal("a token without token_use mcp_session is not a gateway session")
	}
	if got, ok := gatewaySession(toolsSince).MCPSessionStart(); !ok || !got.Equal(toolsSince) {
		t.Fatalf("MCPSessionStart = %v, %v", got, ok)
	}
}
