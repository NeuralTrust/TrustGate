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
	"sync"
	"sync/atomic"
	"testing"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
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
