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

package oauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
	"github.com/stretchr/testify/require"
)

const (
	cimdRedirect = "https://oauth.gw.example/oauth/callback/io.aircall/mcp"
	cimdClientID = "https://oauth.gw.example/oauth/client-metadata/io.aircall/mcp"
)

func cimdServer() *appoauth.UpstreamAuthServer {
	return &appoauth.UpstreamAuthServer{
		Issuer:                            "https://id.aircall.example/as/mcp",
		ValidatedIssuer:                   "https://id.aircall.example/as/mcp",
		AuthorizationEndpoint:             "https://id.aircall.example/as/mcp/oauth/authorize",
		TokenEndpoint:                     "https://id.aircall.example/as/mcp/oauth/token",
		ClientIDMetadataDocumentSupported: true,
	}
}

// Aircall's metadata: no registration_endpoint, and the flag that says it takes
// a client_id URL instead.
func TestDiscover_ReadsClientIDMetadataDocumentSupport(t *testing.T) {
	t.Parallel()
	var srvURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              srvURL + "/mcp",
			"authorization_servers": []string{srvURL + "/as/mcp"},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server/as/mcp", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srvURL + "/as/mcp",
			"authorization_endpoint":                srvURL + "/as/mcp/oauth/authorize",
			"token_endpoint":                        srvURL + "/as/mcp/oauth/token",
			"code_challenge_methods_supported":      []string{"S256"},
			"token_endpoint_auth_methods_supported": []string{"none"},
			"client_id_metadata_document_supported": true,
		})
	})
	srv := httptest.NewServer(mux)
	srvURL = srv.URL
	t.Cleanup(srv.Close)

	r := infraoauth.NewUpstreamRegistrar(newClaimStore(), srv.Client())
	meta, err := r.Discover(context.Background(), srv.URL+"/mcp")
	require.NoError(t, err)
	require.True(t, meta.ClientIDMetadataDocumentSupported)
	require.Empty(t, meta.RegistrationEndpoint)
}

// With no registration endpoint, the client is the gateway's document URL. No
// request goes upstream, and the row is claimed like a registration so every
// replica and later connect reads the same client.
func TestEnsureClient_MetadataDocumentClientNeedsNoRegistration(t *testing.T) {
	t.Parallel()
	var upstream atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstream.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	store := newClaimStore()
	r := infraoauth.NewUpstreamRegistrar(store, srv.Client())
	ctx := context.Background()

	got, err := r.EnsureClient(ctx, "gw|reg", cimdServer(), cimdRedirect)
	require.NoError(t, err)
	require.Equal(t, cimdClientID, got.ClientID)
	require.Empty(t, got.ClientSecret)
	require.Equal(t, cimdRedirect, got.RedirectURI)
	require.Equal(t, infraoauth.DefaultClientName, got.ClientName)
	require.Equal(t, "https://id.aircall.example/as/mcp", got.Issuer)
	require.Empty(t, got.RegistrationEndpoint)
	require.Zero(t, got.ClientSecretExpiresAt)

	again, err := r.EnsureClient(ctx, "gw|reg", cimdServer(), cimdRedirect)
	require.NoError(t, err)
	require.Equal(t, cimdClientID, again.ClientID)
	cached, err := r.CachedClient(ctx, "gw|reg")
	require.NoError(t, err)
	require.Equal(t, cimdClientID, cached.ClientID)

	require.Zero(t, upstream.Load())
	saves, claims, swaps := store.counts()
	require.Equal(t, 0, saves)
	require.Equal(t, 1, claims)
	require.Equal(t, 0, swaps)
}

// A server that offers both keeps registering: switching would replace every
// client already registered there and strand its refresh tokens.
func TestEnsureClient_RegistrationEndpointWinsOverMetadataDocument(t *testing.T) {
	t.Parallel()
	var issued atomic.Int64
	idp := registrationIDP(t, &issued)
	meta := cimdServer()
	meta.RegistrationEndpoint = idp.URL
	r := infraoauth.NewUpstreamRegistrar(newClaimStore(), idp.Client())

	got, err := r.EnsureClient(context.Background(), "gw|reg", meta, cimdRedirect)
	require.NoError(t, err)
	require.Equal(t, "client-1", got.ClientID)
	require.Equal(t, idp.URL, got.RegistrationEndpoint)
	require.EqualValues(t, 1, issued.Load())
}

// Without either a registration endpoint or the document flag there is still
// no client to be had. The same holds when there is no document for the
// redirect URI: the draft requires an https client_id, and a provider id the
// URL cannot carry as written has none.
func TestEnsureClient_NoClientWithoutRegistrationOrDocument(t *testing.T) {
	t.Parallel()
	noFlag := cimdServer()
	noFlag.ClientIDMetadataDocumentSupported = false
	for name, tc := range map[string]struct {
		meta     *appoauth.UpstreamAuthServer
		redirect string
	}{
		"no document support": {meta: noFlag, redirect: cimdRedirect},
		"http redirect":       {meta: cimdServer(), redirect: "http://gw.example/oauth/callback/io.aircall/mcp"},
		"escaped provider":    {meta: cimdServer(), redirect: "https://gw.example/oauth/callback/io.aircall%2Fmcp"},
		"not a callback":      {meta: cimdServer(), redirect: "https://gw.example/oauth/callback"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store := newClaimStore()
			r := infraoauth.NewUpstreamRegistrar(store, nil)
			_, err := r.EnsureClient(context.Background(), "gw|reg", tc.meta, tc.redirect)
			require.ErrorIs(t, err, appoauth.ErrUpstreamNotDiscoverable)
			_, claims, swaps := store.counts()
			require.Zero(t, claims+swaps)
		})
	}
}

// A dropped or renamed document client comes back under the same client_id:
// the row is swapped in place and nothing is stranded.
func TestEnsureClient_MetadataDocumentClientIsRestoredInPlace(t *testing.T) {
	t.Parallel()
	store := newClaimStore()
	ctx := context.Background()
	r := infraoauth.NewUpstreamRegistrar(store, nil)

	first, err := r.EnsureClient(ctx, "gw|reg", cimdServer(), cimdRedirect)
	require.NoError(t, err)
	require.NoError(t, r.DropCachedClient(ctx, "gw|reg", first.ClientID))
	dropped, err := r.CachedClient(ctx, "gw|reg")
	require.NoError(t, err)
	require.Nil(t, dropped)

	restored, err := r.EnsureClient(ctx, "gw|reg", cimdServer(), cimdRedirect)
	require.NoError(t, err)
	require.Equal(t, cimdClientID, restored.ClientID)
	require.Zero(t, restored.ClientSecretExpiresAt)

	renamed, err := infraoauth.NewUpstreamRegistrar(store, nil, infraoauth.WithClientName("TrustGate dev")).
		EnsureClient(ctx, "gw|reg", cimdServer(), cimdRedirect)
	require.NoError(t, err)
	require.Equal(t, cimdClientID, renamed.ClientID)
	require.Equal(t, "TrustGate dev", renamed.ClientName)

	_, claims, swaps := store.counts()
	require.Equal(t, 1, claims)
	require.Equal(t, 3, swaps, "the drop, the restore, and the rename each swap the row")
}

// A server that dropped its registration endpoint for documents gets the
// document client in the slot its registered client held.
func TestEnsureClient_RegisteredClientGivesWayToMetadataDocument(t *testing.T) {
	t.Parallel()
	store := newClaimStore()
	seedClient(t, store, appoauth.RegisteredClient{
		ClientID:              "registered",
		RedirectURI:           cimdRedirect,
		ClientName:            infraoauth.DefaultClientName,
		Issuer:                "https://id.aircall.example/as/mcp",
		RegistrationEndpoint:  "https://id.aircall.example/as/mcp/register",
		ClientSecretExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	r := infraoauth.NewUpstreamRegistrar(store, nil)

	got, err := r.EnsureClient(context.Background(), "gw|reg", cimdServer(), cimdRedirect)
	require.NoError(t, err)
	require.Equal(t, cimdClientID, got.ClientID)
	require.Empty(t, got.RegistrationEndpoint)
	_, claims, swaps := store.counts()
	require.Equal(t, 0, claims)
	require.Equal(t, 1, swaps)
}

func TestRegisteredClientName_MatchesWhatTheRegistrarSends(t *testing.T) {
	t.Parallel()
	require.Equal(t, infraoauth.DefaultClientName, infraoauth.RegisteredClientName(""))
	require.Equal(t, infraoauth.DefaultClientName, infraoauth.RegisteredClientName(" ()! "))
	require.Equal(t, "TrustGate MCP Gateway dev", infraoauth.RegisteredClientName("TrustGate MCP Gateway (dev)"))
}
