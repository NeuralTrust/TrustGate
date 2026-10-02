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
	"net/http/httptest"
	"net/url"
	"testing"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	oidcauth "github.com/NeuralTrust/TrustGate/pkg/infra/auth/oidc"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard/netguardtest"
	"github.com/stretchr/testify/require"
)

const trustedResource = "http://gw.example.com/store/mcp"

// guardedDefaultIdP wires the default IdP exactly as production does (no
// injected client, so the guarded default applies) against a platform on
// loopback. trusted=false turns the same record into what a tenant could
// configure: identical URLs, no operator provenance.
func guardedDefaultIdP(t *testing.T, idp *httptest.Server, issuer string, trusted bool) (AuthProxy, context.Context) {
	t.Helper()
	def := appauth.BuildDefaultIdP(appauth.DefaultIdPConfig{
		Issuer:       issuer,
		AuthorizeURL: idp.URL + "/authorize",
		TokenURL:     idp.URL + "/token",
		JWKSURL:      idp.URL + "/jwks",
		ClientID:     "trustgate",
		Audiences:    []string{"neuraltrust-mcp"},
	})
	def.Config.OAuth2.Trusted = trusted
	paths := &fakePathResolver{byPath: map[string][]appconsumer.PathMatch{
		"/store/mcp": {{GatewayID: ids.GatewayID{}}},
	}}
	finder := &fakeCredentialFinder{oauth2: []*authdomain.Auth{def}, defaultIdP: def}
	proxy := NewAuthProxy(finder, paths, nil, newMemFlowStore(), nil, newTestSigner(t), nil,
		WithIdPTokenVerifier(oidcauth.NewVerifier()))
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind]()}
	return proxy, appgateway.WithGateway(context.Background(), gw)
}

func loginAt(t *testing.T, proxy AuthProxy, ctx context.Context) (string, error) {
	t.Helper()
	loc, err := proxy.Authorize(ctx, "http://gw.example.com", AuthorizeRequest{
		ResponseType: "code", ClientID: "trustgate", RedirectURI: "cursor://anysphere.cursor-mcp/oauth/callback",
		State: "s", CodeChallenge: s256("v"), CodeChallengeMethod: "S256", Resource: trustedResource,
	})
	require.NoError(t, err)
	u, err := url.Parse(loc)
	require.NoError(t, err)
	return proxy.Callback(ctx, "http://gw.example.com", u.Query().Get("state"), "platform-code", "", "")
}

// The dev regression: MCP_DEFAULT_IDP_ISSUER resolves to a private address
// in-cluster. With the guard on, the operator's IdP must still work through the
// whole brokered login and refresh, while a tenant record naming the same
// addresses is refused.
func TestDefaultIdP_BrokeredLoginAndRefreshWorkOnAPrivateAddress(t *testing.T) {
	netguardtest.Deny(t)
	platform := newTestSigner(t)
	token := platformToken(t, platform, map[string]any{"sub": "u1", "aud": "neuraltrust-mcp"})
	idp := platformIdP(t, token, platform.JWKS())

	t.Run("operator default IdP", func(t *testing.T) {
		proxy, ctx := guardedDefaultIdP(t, idp, platform.Issuer(), true)
		loc, err := loginAt(t, proxy, ctx)
		require.NoError(t, err, "callback: token call, JWKS fetch and verification all reach the private IdP")
		require.NotEmpty(t, loc)

		got, err := proxy.Exchange(ctx, "http://gw.example.com", TokenRequest{
			GrantType: "refresh_token", RefreshToken: "idp-refresh", Resource: trustedResource,
		})
		require.NoError(t, err, "refresh reaches the private token endpoint")
		require.Equal(t, token, got["access_token"])
	})

	t.Run("same URLs on a tenant record are refused", func(t *testing.T) {
		proxy, ctx := guardedDefaultIdP(t, idp, platform.Issuer(), false)
		_, err := loginAt(t, proxy, ctx)
		require.ErrorIs(t, err, netguard.ErrBlockedDestination)

		_, err = proxy.Exchange(ctx, "http://gw.example.com", TokenRequest{
			GrantType: "refresh_token", RefreshToken: "idp-refresh", Resource: trustedResource,
		})
		require.ErrorIs(t, err, netguard.ErrBlockedDestination)
	})
}

// A tenant that names the operator's issuer string must not read the AS
// metadata the operator's fetch cached.
func TestASMetadataCacheIsKeyedByTrust(t *testing.T) {
	netguardtest.Deny(t)
	idp, _ := fakeIdP(t)
	p, ok := NewAuthProxy(nil, nil, nil, nil, nil, nil, nil).(*authProxy)
	require.True(t, ok)
	cfg := &authdomain.OAuth2Config{Issuer: idp.URL}

	_, err := p.idp.endpoints(netguard.TrustedIf(context.Background(), true), cfg)
	require.NoError(t, err)
	_, err = p.idp.endpoints(netguard.TrustedIf(context.Background(), false), cfg)
	require.ErrorIs(t, err, netguard.ErrBlockedDestination, "the operator's cached metadata must not serve a tenant")
}
