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
	"net/http"
	"net/url"
	"testing"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/require"
)

// The MCP Store resolves to a synthetic no-auth match with a ZERO gateway
// (mirrors storeMatches), so authForResource returns the platform-wide default
// IdP, which carries no gateway of its own. Authorize must bind the addressed
// gateway (from the request context) into the parked authorization, so the
// session minted at callback stamps that gateway into its gwid claim. Without
// this the gwid is the zero id and the auth chain rejects the token at
// /store/mcp (401), which the MCP client retries forever ("Exchanging token…").
func TestAuthorizeDefaultIdPBindsAddressedGatewayIntoPending(t *testing.T) {
	def := appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{
		Issuer: "https://idp.example.com", ClientID: "trustgate",
	})
	require.True(t, def.GatewayID.IsNil(), "the default IdP has no gateway of its own")

	paths := &fakePathResolver{byPath: map[string][]appconsumer.PathMatch{
		"/store/mcp": {{GatewayID: ids.GatewayID{}}},
	}}
	store := newMemFlowStore()
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{def}, defaultIdP: def}
	proxy := NewAuthProxy(finder, paths, http.DefaultClient, store, nil, nil, nil)

	gw := ids.New[ids.GatewayKind]()
	ctx := appgateway.WithGateway(context.Background(), &gatewaydomain.Gateway{ID: gw})

	loc, err := proxy.Authorize(ctx, "http://gw.example.com", AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "trustgate",
		RedirectURI:         "cursor://anysphere.cursor-mcp/oauth/callback",
		State:               "client-state",
		CodeChallenge:       s256("client-verifier"),
		CodeChallengeMethod: "S256",
		Resource:            "http://gw.example.com/store/mcp",
	})
	require.NoError(t, err)

	parsed, err := url.Parse(loc)
	require.NoError(t, err)
	pending, err := store.TakePending(context.Background(), parsed.Query().Get("state"))
	require.NoError(t, err)
	require.NotNil(t, pending)
	require.Equal(t, gw.String(), pending.GatewayID,
		"authorize must bind the addressed gateway into pending, not the default IdP's zero id")
}

// The default IdP login must carry the addressed gateway's owning tenant to the
// app as an `org` hint, so the app mints the session for that tenant (after
// verifying membership) rather than the user's active org — otherwise the
// cross-tenant guard rejects the session at the MCP plane.
func TestAuthorizeDefaultIdPPassesGatewayTenantAsOrgHint(t *testing.T) {
	def := appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{
		Issuer: "https://idp.example.com", ClientID: "trustgate",
	})
	paths := &fakePathResolver{byPath: map[string][]appconsumer.PathMatch{
		"/store/mcp": {{GatewayID: ids.GatewayID{}}},
	}}
	store := newMemFlowStore()
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{def}, defaultIdP: def}
	proxy := NewAuthProxy(finder, paths, http.DefaultClient, store, nil, nil, nil)

	const tenant = "3b6c66f8-3841-459f-8846-45e47c98056e"
	gw := &gatewaydomain.Gateway{
		ID:       ids.New[ids.GatewayKind](),
		Metadata: gatewaydomain.WithTenantID(nil, tenant),
	}
	ctx := appgateway.WithGateway(context.Background(), gw)

	loc, err := proxy.Authorize(ctx, "http://gw.example.com", AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "trustgate",
		RedirectURI:         "cursor://anysphere.cursor-mcp/oauth/callback",
		State:               "client-state",
		CodeChallenge:       s256("client-verifier"),
		CodeChallengeMethod: "S256",
		Resource:            "http://gw.example.com/store/mcp",
	})
	require.NoError(t, err)

	parsed, err := url.Parse(loc)
	require.NoError(t, err)
	require.Equal(t, tenant, parsed.Query().Get("org"),
		"authorize must pass the gateway's tenant as the org hint to the app")
}

// Without a routed gateway in context there is nothing to bind, so the parked
// authorization keeps the default IdP's zero gateway (unchanged behaviour).
func TestAuthorizeDefaultIdPNoContextGatewayKeepsZero(t *testing.T) {
	def := appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{
		Issuer: "https://idp.example.com", ClientID: "trustgate",
	})
	paths := &fakePathResolver{byPath: map[string][]appconsumer.PathMatch{
		"/store/mcp": {{GatewayID: ids.GatewayID{}}},
	}}
	store := newMemFlowStore()
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{def}, defaultIdP: def}
	proxy := NewAuthProxy(finder, paths, http.DefaultClient, store, nil, nil, nil)

	loc, err := proxy.Authorize(context.Background(), "http://gw.example.com", AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "trustgate",
		RedirectURI:         "cursor://anysphere.cursor-mcp/oauth/callback",
		State:               "client-state",
		CodeChallenge:       s256("client-verifier"),
		CodeChallengeMethod: "S256",
		Resource:            "http://gw.example.com/store/mcp",
	})
	require.NoError(t, err)

	parsed, err := url.Parse(loc)
	require.NoError(t, err)
	pending, err := store.TakePending(context.Background(), parsed.Query().Get("state"))
	require.NoError(t, err)
	require.NotNil(t, pending)
	require.Equal(t, ids.GatewayID{}.String(), pending.GatewayID)
}
