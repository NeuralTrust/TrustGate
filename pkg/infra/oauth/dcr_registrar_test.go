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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
	"github.com/stretchr/testify/require"
)

// claimStore models the shared registration slot: SaveClientIfAbsent is atomic,
// as the Redis SETNX behind it is.
type claimStore struct {
	mu      sync.Mutex
	clients map[string]appoauth.RegisteredClient
	saves   int
	claims  int
	swaps   int
}

func newClaimStore() *claimStore {
	return &claimStore{clients: map[string]appoauth.RegisteredClient{}}
}

func (s *claimStore) SaveClient(_ context.Context, key string, c appoauth.RegisteredClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[key] = c
	s.saves++
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
	s.claims++
	return &c, nil
}

func (s *claimStore) ReplaceClientIfMatch(_ context.Context, key, expectedClientID string, next appoauth.RegisteredClient) (*appoauth.RegisteredClient, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.clients[key]
	if !ok || existing.ClientID != expectedClientID {
		if !ok {
			return nil, false, nil
		}
		return &existing, false, nil
	}
	s.clients[key] = next
	s.swaps++
	return &next, true, nil
}

func (s *claimStore) counts() (saves, claims, swaps int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saves, s.claims, s.swaps
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

// A configured client name goes out in the registration and a later name change
// re-registers, so each environment owns its own upstream app. Rows written
// before the name was recorded stay valid under the default name.
func TestEnsureClient_ClientNameIsConfigurableAndChangesReregister(t *testing.T) {
	t.Parallel()
	var issued atomic.Int64
	var names []string
	var mu sync.Mutex
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			ClientName string `json:"client_name"`
		}
		_ = json.NewDecoder(req.Body).Decode(&body)
		mu.Lock()
		names = append(names, body.ClientName)
		mu.Unlock()
		n := issued.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"client_id": fmt.Sprintf("client-%d", n)})
	}))
	defer idp.Close()

	store := newClaimStore()
	meta := &appoauth.UpstreamAuthServer{RegistrationEndpoint: idp.URL}
	ctx := context.Background()
	redirect := "https://gw.example.com/oauth/callback/p"

	// Legacy row: registered before the name was recorded.
	require.NoError(t, store.SaveClient(ctx, "gw|reg", appoauth.RegisteredClient{ClientID: "legacy", RedirectURI: redirect}))

	// Default name: the legacy row is reused, nothing is registered.
	def := infraoauth.NewUpstreamRegistrar(store, idp.Client())
	kept, err := def.EnsureClient(ctx, "gw|reg", meta, redirect)
	require.NoError(t, err)
	require.Equal(t, "legacy", kept.ClientID)
	require.EqualValues(t, 0, issued.Load())

	// A dev-specific name: re-registers under that name.
	dev := infraoauth.NewUpstreamRegistrar(store, idp.Client(), infraoauth.WithClientName("TrustGate MCP Gateway - dev"))
	renamed, err := dev.EnsureClient(ctx, "gw|reg", meta, redirect)
	require.NoError(t, err)
	require.NotEqual(t, "legacy", renamed.ClientID)
	require.Equal(t, "TrustGate MCP Gateway - dev", renamed.ClientName)
	mu.Lock()
	require.Equal(t, []string{"TrustGate MCP Gateway - dev"}, names)
	mu.Unlock()

	// Same name again: reused.
	again, err := dev.EnsureClient(ctx, "gw|reg", meta, redirect)
	require.NoError(t, err)
	require.Equal(t, renamed.ClientID, again.ClientID)
	require.EqualValues(t, 1, issued.Load())

	// A blank option keeps the default name.
	blank := infraoauth.NewUpstreamRegistrar(newClaimStore(), idp.Client(), infraoauth.WithClientName("  "))
	fresh, err := blank.EnsureClient(ctx, "gw|other", meta, redirect)
	require.NoError(t, err)
	require.Equal(t, infraoauth.DefaultClientName, fresh.ClientName)
}

// Calendly refuses a client_name with anything but letters, digits, hyphens and
// spaces, and refuses the whole registration with it. A configured name is
// reduced to that set so one strict upstream cannot break every connect.
func TestEnsureClient_ClientNameIsReducedToPortableCharacters(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"TrustGate MCP Gateway (dev)": "TrustGate MCP Gateway dev",
		"TrustGate_MCP.Gateway":       "TrustGate MCP Gateway",
		"  NeuralTrust -  sandbox ":   "NeuralTrust - sandbox",
		"()":                          infraoauth.DefaultClientName,
	}
	for configured, want := range cases {
		t.Run(configured, func(t *testing.T) {
			t.Parallel()
			var got string
			idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				var body struct {
					ClientName string `json:"client_name"`
				}
				_ = json.NewDecoder(req.Body).Decode(&body)
				got = body.ClientName
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{"client_id": "c"})
			}))
			defer idp.Close()
			r := infraoauth.NewUpstreamRegistrar(newClaimStore(), idp.Client(), infraoauth.WithClientName(configured))
			client, err := r.EnsureClient(context.Background(), "gw|reg",
				&appoauth.UpstreamAuthServer{RegistrationEndpoint: idp.URL}, "https://gw.example.com/oauth/callback/p")
			require.NoError(t, err)
			require.Equal(t, want, got)
			require.Equal(t, want, client.ClientName)
		})
	}
}

// An upstream that refuses the registration answers with a 4xx; the error has
// to say so in a way callers can tell apart from a gateway fault.
func TestEnsureClient_RejectedRegistrationIsTyped(t *testing.T) {
	t.Parallel()
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client_metadata"}`))
	}))
	defer idp.Close()
	r := infraoauth.NewUpstreamRegistrar(newClaimStore(), idp.Client())
	_, err := r.EnsureClient(context.Background(), "gw|reg",
		&appoauth.UpstreamAuthServer{RegistrationEndpoint: idp.URL}, "https://gw.example.com/oauth/callback/p")
	require.ErrorIs(t, err, appoauth.ErrUpstreamRegistrationRejected)
	require.Contains(t, err.Error(), "status 400")
	require.Contains(t, err.Error(), "invalid_client_metadata")
}

func registrationIDP(t *testing.T, issued *atomic.Int64) *httptest.Server {
	t.Helper()
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := issued.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_id":                fmt.Sprintf("client-%d", n),
			"client_secret_expires_at": time.Now().Add(time.Hour).Unix(),
		})
	}))
	t.Cleanup(idp.Close)
	return idp
}

func seedClient(t *testing.T, store *claimStore, c appoauth.RegisteredClient) {
	t.Helper()
	require.NoError(t, store.SaveClient(context.Background(), "gw|reg", c))
}

// A cached client registered at another authorization server is not reusable,
// even when the redirect URI and client name still match. Replacement swaps the
// stored row only while it is still that client, rather than racing a fresh claim.
func TestEnsureClient_DifferentIssuerReregisters(t *testing.T) {
	t.Parallel()
	var issued atomic.Int64
	idp := registrationIDP(t, &issued)
	store := newClaimStore()
	redirect := "https://gw.example.com/oauth/callback/p"
	seedClient(t, store, appoauth.RegisteredClient{
		ClientID:              "stale",
		RedirectURI:           redirect,
		ClientName:            infraoauth.DefaultClientName,
		Issuer:                "https://old.example",
		RegistrationEndpoint:  idp.URL,
		ClientSecretExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	r := infraoauth.NewUpstreamRegistrar(store, idp.Client())
	got, err := r.EnsureClient(context.Background(), "gw|reg", &appoauth.UpstreamAuthServer{
		Issuer:               "https://new.example",
		RegistrationEndpoint: idp.URL,
	}, redirect)
	require.NoError(t, err)
	require.NotEqual(t, "stale", got.ClientID)
	require.Equal(t, "https://new.example", got.Issuer)
	require.EqualValues(t, 1, issued.Load())
	saves, claims, swaps := store.counts()
	require.Equal(t, 1, saves, "seeding the row is the only blind write")
	require.Equal(t, 0, claims, "replacement must not open a fresh registration race")
	require.Equal(t, 1, swaps, "replacement must swap the stored client")
}

func TestEnsureClient_DifferentRegistrationEndpointReregisters(t *testing.T) {
	t.Parallel()
	var issued atomic.Int64
	idp := registrationIDP(t, &issued)
	store := newClaimStore()
	redirect := "https://gw.example.com/oauth/callback/p"
	seedClient(t, store, appoauth.RegisteredClient{
		ClientID:             "stale",
		RedirectURI:          redirect,
		ClientName:           infraoauth.DefaultClientName,
		Issuer:               "https://as.example",
		RegistrationEndpoint: "https://old.example/register",
	})
	r := infraoauth.NewUpstreamRegistrar(store, idp.Client())
	got, err := r.EnsureClient(context.Background(), "gw|reg", &appoauth.UpstreamAuthServer{
		Issuer:               "https://as.example",
		RegistrationEndpoint: idp.URL,
	}, redirect)
	require.NoError(t, err)
	require.NotEqual(t, "stale", got.ClientID)
	require.Equal(t, idp.URL, got.RegistrationEndpoint)
	require.EqualValues(t, 1, issued.Load())
	_, claims, swaps := store.counts()
	require.Equal(t, 0, claims)
	require.Equal(t, 1, swaps)
}

func TestEnsureClient_ExpiredRegistrationReregisters(t *testing.T) {
	t.Parallel()
	var issued atomic.Int64
	idp := registrationIDP(t, &issued)
	store := newClaimStore()
	redirect := "https://gw.example.com/oauth/callback/p"
	meta := &appoauth.UpstreamAuthServer{Issuer: "https://as.example", RegistrationEndpoint: idp.URL}
	seedClient(t, store, appoauth.RegisteredClient{
		ClientID:              "stale",
		RedirectURI:           redirect,
		ClientName:            infraoauth.DefaultClientName,
		Issuer:                meta.Issuer,
		RegistrationEndpoint:  meta.RegistrationEndpoint,
		ClientSecretExpiresAt: time.Now().Add(-time.Minute).Unix(),
	})
	r := infraoauth.NewUpstreamRegistrar(store, idp.Client())
	got, err := r.EnsureClient(context.Background(), "gw|reg", meta, redirect)
	require.NoError(t, err)
	require.NotEqual(t, "stale", got.ClientID)
	require.EqualValues(t, 1, issued.Load())
	saves, claims, swaps := store.counts()
	require.Equal(t, 1, saves)
	require.Equal(t, 0, claims)
	require.Equal(t, 1, swaps)
}

// A client bound to this server, with a registration that has not expired, is
// reused. So is a row written before the server was recorded: an empty issuer
// is not treated as a different server.
func TestEnsureClient_BoundUnexpiredClientIsReused(t *testing.T) {
	t.Parallel()
	var issued atomic.Int64
	idp := registrationIDP(t, &issued)
	store := newClaimStore()
	redirect := "https://gw.example.com/oauth/callback/p"
	meta := &appoauth.UpstreamAuthServer{Issuer: "https://as.example", RegistrationEndpoint: idp.URL}
	r := infraoauth.NewUpstreamRegistrar(store, idp.Client())
	ctx := context.Background()

	first, err := r.EnsureClient(ctx, "gw|reg", meta, redirect)
	require.NoError(t, err)
	require.Equal(t, meta.Issuer, first.Issuer)
	require.Equal(t, meta.RegistrationEndpoint, first.RegistrationEndpoint)
	require.Greater(t, first.ClientSecretExpiresAt, time.Now().Unix())

	again, err := r.EnsureClient(ctx, "gw|reg", meta, redirect)
	require.NoError(t, err)
	require.Equal(t, first.ClientID, again.ClientID)
	require.EqualValues(t, 1, issued.Load())

	seedClient(t, store, appoauth.RegisteredClient{
		ClientID:    "legacy",
		RedirectURI: redirect,
		ClientName:  infraoauth.DefaultClientName,
	})
	legacy, err := r.EnsureClient(ctx, "gw|reg", meta, redirect)
	require.NoError(t, err)
	require.Equal(t, "legacy", legacy.ClientID)
	require.EqualValues(t, 1, issued.Load())
}

func TestDropCachedClient_NextEnsureClientReplaces(t *testing.T) {
	t.Parallel()
	var issued atomic.Int64
	idp := registrationIDP(t, &issued)
	store := newClaimStore()
	redirect := "https://gw.example.com/oauth/callback/p"
	meta := &appoauth.UpstreamAuthServer{Issuer: "https://as.example", RegistrationEndpoint: idp.URL}
	r := infraoauth.NewUpstreamRegistrar(store, idp.Client())
	ctx := context.Background()

	first, err := r.EnsureClient(ctx, "gw|reg", meta, redirect)
	require.NoError(t, err)
	require.NoError(t, r.DropCachedClient(ctx, "gw|reg", first.ClientID))

	cached, err := r.CachedClient(ctx, "gw|reg")
	require.NoError(t, err)
	require.Nil(t, cached, "a rejected client is no longer usable")
	raw, err := store.GetClient(ctx, "gw|reg")
	require.NoError(t, err)
	require.NotNil(t, raw, "the row stays so the next registration replaces it")
	require.Equal(t, first.ClientID, raw.ClientID)
	require.Positive(t, raw.ClientSecretExpiresAt)
	require.LessOrEqual(t, raw.ClientSecretExpiresAt, time.Now().Unix())

	second, err := r.EnsureClient(ctx, "gw|reg", meta, redirect)
	require.NoError(t, err)
	require.NotEqual(t, first.ClientID, second.ClientID)
	require.EqualValues(t, 2, issued.Load())
	_, claims, swaps := store.counts()
	require.Equal(t, 2, swaps, "drop and the following EnsureClient both swap the stored client")
	require.Equal(t, 1, claims, "the replacement must not claim a fresh slot")
}

func TestDropCachedClient_ClearsRefreshRetained(t *testing.T) {
	t.Parallel()
	store := newClaimStore()
	ctx := context.Background()
	require.NoError(t, store.SaveClient(ctx, "gw|reg", appoauth.RegisteredClient{
		ClientID:              "client-a",
		ClientSecret:          "legacy-secret",
		ClientSecretExpiresAt: time.Now().Add(time.Hour).Unix(),
		RefreshRetained:       true,
	}))
	r := infraoauth.NewUpstreamRegistrar(store, nil)

	require.NoError(t, r.DropCachedClient(ctx, "gw|reg", "client-a"))

	got, err := store.GetClient(ctx, "gw|reg")
	require.NoError(t, err)
	require.Equal(t, "client-a", got.ClientID)
	require.Equal(t, "legacy-secret", got.ClientSecret)
	require.False(t, got.RefreshRetained)
	require.EqualValues(t, 1, got.ClientSecretExpiresAt)
}

func TestDropCachedClient_StaleClientIDIsIgnored(t *testing.T) {
	t.Parallel()
	store := newClaimStore()
	ctx := context.Background()
	current := appoauth.RegisteredClient{
		ClientID:              "client-b",
		ClientSecretExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	require.NoError(t, store.SaveClient(ctx, "gw|reg", current))
	r := infraoauth.NewUpstreamRegistrar(store, nil)

	require.NoError(t, r.DropCachedClient(ctx, "gw|reg", "client-a"))

	got, err := store.GetClient(ctx, "gw|reg")
	require.NoError(t, err)
	require.Equal(t, "client-b", got.ClientID)
	require.Greater(t, got.ClientSecretExpiresAt, time.Now().Unix())
}

func TestDropAndReplace_ConcurrentClientsStayConsistent(t *testing.T) {
	t.Parallel()
	store := newClaimStore()
	ctx := context.Background()
	require.NoError(t, store.SaveClient(ctx, "gw|reg", appoauth.RegisteredClient{
		ClientID:              "client-a",
		ClientSecretExpiresAt: time.Now().Add(time.Hour).Unix(),
	}))
	replacement := appoauth.RegisteredClient{
		ClientID:              "client-b",
		ClientSecretExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	r := infraoauth.NewUpstreamRegistrar(store, nil)

	var wg sync.WaitGroup
	const n = 32
	for range n {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = r.DropCachedClient(ctx, "gw|reg", "client-a")
		}()
		go func() {
			defer wg.Done()
			_, _, _ = store.ReplaceClientIfMatch(ctx, "gw|reg", "client-a", replacement)
		}()
	}
	wg.Wait()

	got, err := store.GetClient(ctx, "gw|reg")
	require.NoError(t, err)
	require.NotNil(t, got)
	switch got.ClientID {
	case "client-a":
		require.LessOrEqual(t, got.ClientSecretExpiresAt, time.Now().Unix())
	case "client-b":
		require.Greater(t, got.ClientSecretExpiresAt, time.Now().Unix())
	default:
		t.Fatalf("client_id = %q", got.ClientID)
	}

	require.NoError(t, store.SaveClient(ctx, "gw|reg", replacement))
	require.NoError(t, r.DropCachedClient(ctx, "gw|reg", "client-a"))
	got, err = store.GetClient(ctx, "gw|reg")
	require.NoError(t, err)
	require.Equal(t, "client-b", got.ClientID)
	require.Greater(t, got.ClientSecretExpiresAt, time.Now().Unix())
}

func TestDiscover_NotDiscoverableOmitsQueryAndUserinfo(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	host := strings.TrimPrefix(srv.URL, "http://")
	upstream := "http://user:s3cret@" + host + "/mcp?token=supersecret#frag"
	r := infraoauth.NewUpstreamRegistrar(newClaimStore(), srv.Client())
	_, err := r.Discover(context.Background(), upstream)
	require.ErrorIs(t, err, appoauth.ErrUpstreamNotDiscoverable)
	msg := err.Error()
	require.NotContains(t, msg, "s3cret")
	require.NotContains(t, msg, "user:")
	require.NotContains(t, msg, "?")
	require.NotContains(t, msg, "token=")
	require.NotContains(t, msg, "supersecret")
	require.NotContains(t, msg, "#frag")
	require.Contains(t, msg, "http://"+host+"/mcp")
}

func TestDiscover_SpoofedIssuerIsRefused(t *testing.T) {
	t.Parallel()
	var tokenHits atomic.Int64
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
			"issuer":                 "https://victim.example",
			"authorization_endpoint": srvURL + "/authorize",
			"token_endpoint":         srvURL + "/token",
			"registration_endpoint":  "https://victim.example/register",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		tokenHits.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	})
	srv := httptest.NewServer(mux)
	srvURL = srv.URL
	t.Cleanup(srv.Close)

	r := infraoauth.NewUpstreamRegistrar(newClaimStore(), srv.Client())
	_, err := r.Discover(context.Background(), srv.URL+"/mcp")
	require.Error(t, err)
	require.Contains(t, err.Error(), "issuer does not match")
	require.Zero(t, tokenHits.Load())
}

func TestDiscover_IssuerMatchIgnoresCaseAndTrailingSlash(t *testing.T) {
	t.Parallel()
	var srvURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              srvURL + "/mcp",
			"authorization_servers": []string{srvURL + "/"},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		issuer := "HTTP://" + strings.TrimPrefix(srvURL, "http://") + "/"
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": srvURL + "/authorize",
			"token_endpoint":         srvURL + "/token",
			"registration_endpoint":  srvURL + "/register",
		})
	})
	srv := httptest.NewServer(mux)
	srvURL = srv.URL
	t.Cleanup(srv.Close)

	r := infraoauth.NewUpstreamRegistrar(newClaimStore(), srv.Client())
	meta, err := r.Discover(context.Background(), srv.URL+"/mcp")
	require.NoError(t, err)
	require.Equal(t, srv.URL, meta.ValidatedIssuer)
	require.Equal(t, meta.ValidatedIssuer, meta.Issuer)
}

func TestDiscover_NonHTTPAuthorizationServerIsRefused(t *testing.T) {
	t.Parallel()
	var metadataHits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              "https://evil.example/mcp",
			"authorization_servers": []string{"ftp://evil.example"},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		metadataHits.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	r := infraoauth.NewUpstreamRegistrar(newClaimStore(), srv.Client())
	_, err := r.Discover(context.Background(), srv.URL+"/mcp")
	require.Error(t, err)
	require.Contains(t, err.Error(), "bad authorization server")
	require.Zero(t, metadataHits.Load())
}
