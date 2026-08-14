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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
	"github.com/stretchr/testify/require"
)

// claimStore models the shared registration slot: SaveClientIfAbsent is atomic,
// as the Redis SETNX behind it is.
type claimStore struct {
	mu      sync.Mutex
	clients map[string]appoauth.RegisteredClient
}

func newClaimStore() *claimStore {
	return &claimStore{clients: map[string]appoauth.RegisteredClient{}}
}

func (s *claimStore) SaveClient(_ context.Context, key string, c appoauth.RegisteredClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[key] = c
	return nil
}

func (s *claimStore) GetClient(_ context.Context, key string) (*appoauth.RegisteredClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[key]
	if !ok {
		return nil, nil
	}
	return &c, nil
}

func (s *claimStore) SaveClientIfAbsent(_ context.Context, key string, c appoauth.RegisteredClient) (*appoauth.RegisteredClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.clients[key]; ok {
		return &existing, nil
	}
	s.clients[key] = c
	return &c, nil
}

// Dynamic client registration is not idempotent: every call mints a fresh
// client_id. When several replicas register the same upstream at once they must
// still converge on one client_id — a second one silently strands the refresh
// tokens issued to the first, which resurfaces later as invalid_grant and drags
// the user back through the consent screen.
func TestEnsureClient_ConcurrentReplicasConvergeOnOneClientID(t *testing.T) {
	t.Parallel()
	var issued atomic.Int64
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := issued.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id": fmt.Sprintf("client-%d", n),
		})
	}))
	defer idp.Close()

	store := newClaimStore()
	meta := &appoauth.UpstreamAuthServer{RegistrationEndpoint: idp.URL}
	const replicas = 8
	const redirectURI = "https://gw.example.com/oauth/callback/com.notion/mcp"

	results := make([]*appoauth.RegisteredClient, replicas)
	errs := make([]error, replicas)
	var wg sync.WaitGroup
	for i := range replicas {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// A registrar per goroutine: each models a separate pod, so they share
			// only the store — exactly as replicas do.
			r := infraoauth.NewUpstreamRegistrar(store, idp.Client())
			results[i], errs[i] = r.EnsureClient(context.Background(), "gw|reg", meta, redirectURI)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "replica %d", i)
		require.NotNil(t, results[i], "replica %d", i)
	}
	winner := results[0].ClientID
	for i, got := range results {
		require.Equal(t, winner, got.ClientID,
			"replica %d returned a different client_id; grants issued to the others would be stranded", i)
	}

	stored, err := store.GetClient(context.Background(), "gw|reg")
	require.NoError(t, err)
	require.Equal(t, winner, stored.ClientID, "the stored client must be the one every replica uses")
}

// A genuine redirect-URI change is a deliberate replacement, not a race, and
// must still overwrite the stored client.
func TestEnsureClient_RedirectURIChangeReplacesClient(t *testing.T) {
	t.Parallel()
	var issued atomic.Int64
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := issued.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": fmt.Sprintf("client-%d", n)})
	}))
	defer idp.Close()

	store := newClaimStore()
	meta := &appoauth.UpstreamAuthServer{RegistrationEndpoint: idp.URL}
	r := infraoauth.NewUpstreamRegistrar(store, idp.Client())
	ctx := context.Background()

	first, err := r.EnsureClient(ctx, "gw|reg", meta, "https://gw.example.com/oauth/callback/p")
	require.NoError(t, err)

	// Same redirect URI: reuses the registration, no new client_id.
	again, err := r.EnsureClient(ctx, "gw|reg", meta, "https://gw.example.com/oauth/callback/p")
	require.NoError(t, err)
	require.Equal(t, first.ClientID, again.ClientID)

	// Different redirect URI: deliberate re-registration.
	moved, err := r.EnsureClient(ctx, "gw|reg", meta, "https://new.example.com/oauth/callback/p")
	require.NoError(t, err)
	require.NotEqual(t, first.ClientID, moved.ClientID)
	stored, err := store.GetClient(ctx, "gw|reg")
	require.NoError(t, err)
	require.Equal(t, moved.ClientID, stored.ClientID)
}

func TestEnsureClient_StampsEmptyIssuerWithoutReregister(t *testing.T) {
	t.Parallel()
	var issued atomic.Int64
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := issued.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": fmt.Sprintf("client-%d", n)})
	}))
	defer idp.Close()

	store := newClaimStore()
	const key = "gw|reg"
	const redirect = "https://gw.example.com/oauth/callback/p"
	require.NoError(t, store.SaveClient(context.Background(), key, appoauth.RegisteredClient{
		ClientID:     "pre-1106",
		ClientSecret: "old-secret",
		RedirectURI:  redirect,
	}))
	meta := &appoauth.UpstreamAuthServer{
		Issuer:               "https://as.example",
		RegistrationEndpoint: idp.URL,
	}
	r := infraoauth.NewUpstreamRegistrar(store, idp.Client())
	got, err := r.EnsureClient(context.Background(), key, meta, redirect)
	require.NoError(t, err)
	require.Equal(t, "pre-1106", got.ClientID)
	require.Equal(t, "old-secret", got.ClientSecret)
	require.Equal(t, "https://as.example", got.Issuer)
	require.Equal(t, int64(0), issued.Load())
	stored, err := store.GetClient(context.Background(), key)
	require.NoError(t, err)
	require.Equal(t, "https://as.example", stored.Issuer)
}

func TestEnsureClient_MatchingIssuerReuses(t *testing.T) {
	t.Parallel()
	var issued atomic.Int64
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		issued.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "fresh"})
	}))
	defer idp.Close()

	store := newClaimStore()
	const key = "gw|reg"
	const redirect = "https://gw.example.com/oauth/callback/p"
	require.NoError(t, store.SaveClient(context.Background(), key, appoauth.RegisteredClient{
		ClientID:    "bound-a",
		RedirectURI: redirect,
		Issuer:      "https://as.example",
	}))
	r := infraoauth.NewUpstreamRegistrar(store, idp.Client())
	got, err := r.EnsureClient(context.Background(), key, &appoauth.UpstreamAuthServer{
		Issuer:               "https://as.example/",
		RegistrationEndpoint: idp.URL,
	}, redirect)
	require.NoError(t, err)
	require.Equal(t, "bound-a", got.ClientID)
	require.Equal(t, int64(0), issued.Load())
}

func TestEnsureClient_MismatchReregisters(t *testing.T) {
	var issued atomic.Int64
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := issued.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": fmt.Sprintf("client-%d", n)})
	}))
	defer idp.Close()

	store := newClaimStore()
	const key = "gw|reg"
	const redirect = "https://gw.example.com/oauth/callback/p"
	require.NoError(t, store.SaveClient(context.Background(), key, appoauth.RegisteredClient{
		ClientID:     "bound-a",
		ClientSecret: "secret-a",
		RedirectURI:  redirect,
		Issuer:       "https://as-a.example",
	}))
	logs := captureDCRSlog(t)
	r := infraoauth.NewUpstreamRegistrar(store, idp.Client())
	got, err := r.EnsureClient(context.Background(), key, &appoauth.UpstreamAuthServer{
		Issuer:               "https://as-b.example",
		RegistrationEndpoint: idp.URL,
	}, redirect)
	require.NoError(t, err)
	require.NotEqual(t, "bound-a", got.ClientID)
	require.Equal(t, "https://as-b.example", got.Issuer)
	require.Equal(t, int64(1), issued.Load())
	logged := logs.String()
	require.Contains(t, logged, "oauth.issuer_mismatch")
	require.NotContains(t, logged, "secret-a")
	require.NotContains(t, logged, "client_secret")
}

func TestEnsureClient_SouthboundDCRIsWeb(t *testing.T) {
	t.Parallel()
	var body map[string]any
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "web-client"})
	}))
	defer idp.Close()

	r := infraoauth.NewUpstreamRegistrar(newClaimStore(), idp.Client())
	got, err := r.EnsureClient(context.Background(), "gw|reg", &appoauth.UpstreamAuthServer{
		Issuer:               "https://as.example",
		RegistrationEndpoint: idp.URL,
	}, "https://gw.example.com/oauth/callback/p")
	require.NoError(t, err)
	require.Equal(t, "web-client", got.ClientID)
	require.Equal(t, "web", body["application_type"])
}

func TestDiscover_MetadataIssuerFailClosed(t *testing.T) {
	cases := []struct {
		name    string
		issuer  string
		wantErr bool
	}{
		{name: "matching metadata proceeds", issuer: "", wantErr: false},
		{name: "mismatched metadata fails closed", issuer: "https://attacker.example", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			registerHits := 0
			var srvURL string
			mux := http.NewServeMux()
			mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"resource":              srvURL + "/mcp",
					"authorization_servers": []string{srvURL},
				})
			})
			mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
				iss := tc.issuer
				if iss == "" {
					iss = srvURL
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"issuer":                 iss,
					"authorization_endpoint": srvURL + "/authorize",
					"token_endpoint":         srvURL + "/token",
					"registration_endpoint":  srvURL + "/register",
				})
			})
			mux.HandleFunc("/register", func(w http.ResponseWriter, _ *http.Request) {
				registerHits++
			})
			srv := httptest.NewServer(mux)
			srvURL = srv.URL
			t.Cleanup(srv.Close)

			var logs *dcrSyncBuffer
			if tc.wantErr {
				logs = captureDCRSlog(t)
			}
			r := infraoauth.NewUpstreamRegistrar(newClaimStore(), srv.Client())
			meta, err := r.Discover(context.Background(), srv.URL+"/mcp")
			if tc.wantErr {
				require.Error(t, err)
				require.Equal(t, 0, registerHits)
				require.Contains(t, logs.String(), "oauth.invalid_metadata")
				require.NotContains(t, logs.String(), "client_secret")
				return
			}
			require.NoError(t, err)
			require.True(t, appoauth.IssuersEqual(meta.Issuer, srv.URL))
		})
	}
}

func TestRefreshAuth_MismatchReturnsErrNoRegisteredClient(t *testing.T) {
	registerHits := 0
	var srvURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              srvURL + "/mcp",
			"authorization_servers": []string{srvURL},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srvURL,
			"authorization_endpoint": srvURL + "/authorize",
			"token_endpoint":         srvURL + "/token",
			"registration_endpoint":  srvURL + "/register",
		})
	})
	mux.HandleFunc("/register", func(w http.ResponseWriter, _ *http.Request) {
		registerHits++
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "should-not-issue"})
	})
	srv := httptest.NewServer(mux)
	srvURL = srv.URL
	defer srv.Close()

	gw := ids.New[ids.GatewayKind]()
	reg, err := registrydomain.NewMCPRegistry(gw, "linear-mcp", "", &registrydomain.MCPTarget{
		URL: srv.URL + "/mcp",
		Auth: &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "linear",
			Registration: registrydomain.RegistrationAuto,
		},
	})
	require.NoError(t, err)

	store := newClaimStore()
	key := gw.String() + "|" + reg.ID.String()
	require.NoError(t, store.SaveClient(context.Background(), key, appoauth.RegisteredClient{
		ClientID:    "bound-a",
		RedirectURI: "https://gw.example.com/oauth/callback/linear",
		Issuer:      "https://as-a.example",
	}))

	logs := captureDCRSlog(t)
	registrar := infraoauth.NewUpstreamRegistrar(store, srv.Client())
	svc := appoauth.NewConnectService(nil, nil, nil, nil, registrar)

	_, err = svc.RefreshAuth(context.Background(), gw, reg)
	require.ErrorIs(t, err, appoauth.ErrNoRegisteredClient)
	require.Equal(t, 0, registerHits)
	require.Contains(t, logs.String(), "oauth.issuer_mismatch")
}

type dcrSyncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *dcrSyncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *dcrSyncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func captureDCRSlog(t *testing.T) *dcrSyncBuffer {
	t.Helper()
	buf := &dcrSyncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}
