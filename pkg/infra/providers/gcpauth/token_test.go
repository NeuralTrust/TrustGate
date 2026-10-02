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

package gcpauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/common/gcpkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func serviceAccountJSON(t *testing.T, tokenURI, email string) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	return serviceAccountJSONWithKey(t, key, tokenURI, email)
}

// serviceAccountJSONWithKey builds a service-account credential from a
// caller-supplied RSA key. Tests that need many distinct credentials (e.g.
// exercising cache eviction) share one key here instead of paying RSA
// keygen's cost once per credential; the key's validity as a JWT signer is
// not what those tests are exercising.
func serviceAccountJSONWithKey(t *testing.T, key *rsa.PrivateKey, tokenURI, email string) string {
	t.Helper()

	privateKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	raw, err := json.Marshal(map[string]string{
		"type":         "service_account",
		"project_id":   "careplus-poc",
		"private_key":  string(privateKey),
		"client_email": email,
		"token_uri":    tokenURI,
	})
	require.NoError(t, err)

	return string(raw)
}

func tokenEndpoint(t *testing.T, calls *atomic.Int64) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"access_token":"ya29.minted","token_type":"Bearer","expires_in":3600}`)
	}))
	t.Cleanup(server.Close)

	return server
}

func TestServiceAccountCacheMintsAccessToken(t *testing.T) {
	var calls atomic.Int64
	server := tokenEndpoint(t, &calls)

	token, err := NewServiceAccountCache(WithHTTPClient(redirectTo(server))).Token(context.Background(),
		serviceAccountJSON(t, gcpkey.TokenURL, "sa@careplus-poc.iam.gserviceaccount.com"), CloudPlatformScope)

	require.NoError(t, err)
	assert.Equal(t, "ya29.minted", token)
	assert.Equal(t, int64(1), calls.Load())
}

func TestServiceAccountCacheReusesValidToken(t *testing.T) {
	var calls atomic.Int64
	server := tokenEndpoint(t, &calls)
	cache := NewServiceAccountCache(WithHTTPClient(redirectTo(server)))
	sa := serviceAccountJSON(t, gcpkey.TokenURL, "sa@careplus-poc.iam.gserviceaccount.com")

	for range 5 {
		token, err := cache.Token(context.Background(), sa, CloudPlatformScope)
		require.NoError(t, err)
		assert.Equal(t, "ya29.minted", token)
	}

	assert.Equal(t, int64(1), calls.Load(),
		"a valid access token must be reused instead of signing a new JWT on every request")
}

func TestServiceAccountCacheIsolatesServiceAccounts(t *testing.T) {
	var calls atomic.Int64
	server := tokenEndpoint(t, &calls)
	cache := NewServiceAccountCache(WithHTTPClient(redirectTo(server)))

	for _, email := range []string{"one@careplus-poc.iam.gserviceaccount.com", "two@careplus-poc.iam.gserviceaccount.com"} {
		_, err := cache.Token(context.Background(), serviceAccountJSON(t, gcpkey.TokenURL, email), CloudPlatformScope)
		require.NoError(t, err)
	}

	assert.Equal(t, int64(2), calls.Load(), "each service account needs its own token")
}

func TestServiceAccountCacheIsolatesScopes(t *testing.T) {
	var calls atomic.Int64
	server := tokenEndpoint(t, &calls)
	cache := NewServiceAccountCache(WithHTTPClient(redirectTo(server)))
	sa := serviceAccountJSON(t, gcpkey.TokenURL, "sa@careplus-poc.iam.gserviceaccount.com")

	for _, scope := range []string{CloudPlatformScope, "https://www.googleapis.com/auth/other"} {
		_, err := cache.Token(context.Background(), sa, scope)
		require.NoError(t, err)
	}

	assert.Equal(t, int64(2), calls.Load(), "each scope needs its own token even for the same service account")
}

func TestServiceAccountCacheConcurrentCallers(t *testing.T) {
	var calls atomic.Int64
	server := tokenEndpoint(t, &calls)
	cache := NewServiceAccountCache(WithHTTPClient(redirectTo(server)))
	sa := serviceAccountJSON(t, gcpkey.TokenURL, "sa@careplus-poc.iam.gserviceaccount.com")

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := cache.Token(context.Background(), sa, CloudPlatformScope)
			assert.NoError(t, err)
			assert.Equal(t, "ya29.minted", token)
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(1), calls.Load(), "concurrent requests must share a single token exchange")
}

func TestServiceAccountCacheDefaultsToCloudPlatformScope(t *testing.T) {
	var calls atomic.Int64
	server := tokenEndpoint(t, &calls)
	sa := serviceAccountJSON(t, gcpkey.TokenURL, "sa@careplus-poc.iam.gserviceaccount.com")

	token, err := NewServiceAccountCache(WithHTTPClient(redirectTo(server))).Token(context.Background(), sa, "")

	require.NoError(t, err)
	assert.Equal(t, "ya29.minted", token)
}

func TestServiceAccountCacheEvictsPastCapacity(t *testing.T) {
	var calls atomic.Int64
	server := tokenEndpoint(t, &calls)
	cache := NewServiceAccountCache(WithHTTPClient(redirectTo(server)))

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	for i := range maxCachedTokenSources + 1 {
		email := fmt.Sprintf("sa-%d@careplus-poc.iam.gserviceaccount.com", i)
		_, err := cache.Token(context.Background(), serviceAccountJSONWithKey(t, key, gcpkey.TokenURL, email), CloudPlatformScope)
		require.NoError(t, err)
	}

	cache.mu.RLock()
	size := len(cache.sources)
	cache.mu.RUnlock()
	assert.LessOrEqual(t, size, maxCachedTokenSources, "cache must not grow without bound")
}

func TestServiceAccountCacheErrors(t *testing.T) {
	var calls atomic.Int64
	server := tokenEndpoint(t, &calls)

	rejecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`)
	}))
	t.Cleanup(rejecting.Close)

	tests := []struct {
		name               string
		serviceAccountJSON string
		cancel             bool
		errContains        string
		endpoint           *httptest.Server
	}{
		{name: "empty json", errContains: "required"},
		{
			name:               "malformed json",
			serviceAccountJSON: "{not-json",
			errContains:        "parsing gcp service account credentials",
		},
		{
			name: "external account config is rejected",
			serviceAccountJSON: `{"type":"external_account","audience":"//iam.googleapis.com/x",` +
				`"token_url":"https://sts.googleapis.com/v1/token","credential_source":{"executable":{"command":"/bin/sh -c id"}}}`,
			errContains: "parsing gcp service account credentials",
		},
		{
			name:               "google rejects the assertion",
			serviceAccountJSON: serviceAccountJSON(t, gcpkey.TokenURL, "sa@careplus-poc.iam.gserviceaccount.com"),
			errContains:        "exchanging gcp service account for an access token",
			endpoint:           rejecting,
		},
		{
			name:               "cancelled context",
			serviceAccountJSON: serviceAccountJSON(t, gcpkey.TokenURL, "sa@careplus-poc.iam.gserviceaccount.com"),
			cancel:             true,
			errContains:        "context canceled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancel {
				cancel()
			}

			endpoint := server
			if tt.endpoint != nil {
				endpoint = tt.endpoint
			}
			_, err := NewServiceAccountCache(WithHTTPClient(redirectTo(endpoint))).Token(ctx, tt.serviceAccountJSON, CloudPlatformScope)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

// redirectTo returns a client that sends every request to server, whatever
// host it names. The cache pins the real Google endpoint, so this is how a
// test observes the token exchange without reaching the internet.
func redirectTo(server *httptest.Server) *http.Client {
	return &http.Client{Transport: &redirectTransport{target: server.Listener.Addr().String()}}
}

type redirectTransport struct {
	target string
	hosts  sync.Map
}

func (r *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.hosts.Store(req.URL.String(), struct{}{})
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = r.target
	return http.DefaultTransport.RoundTrip(clone)
}
