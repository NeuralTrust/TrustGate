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

package vertex

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

func serviceAccountJSON(t *testing.T, tokenURI, email string) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

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

func TestTokenCacheMintsAccessToken(t *testing.T) {
	var calls atomic.Int64
	server := tokenEndpoint(t, &calls)

	token, err := newTokenCache().token(context.Background(), &providers.GCP{
		ServiceAccountJSON: serviceAccountJSON(t, server.URL, "sa@careplus-poc.iam.gserviceaccount.com"),
	})

	require.NoError(t, err)
	assert.Equal(t, "ya29.minted", token)
	assert.Equal(t, int64(1), calls.Load())
}

func TestTokenCacheReusesValidToken(t *testing.T) {
	var calls atomic.Int64
	server := tokenEndpoint(t, &calls)
	cache := newTokenCache()
	gcp := &providers.GCP{ServiceAccountJSON: serviceAccountJSON(t, server.URL, "sa@careplus-poc.iam.gserviceaccount.com")}

	for range 5 {
		token, err := cache.token(context.Background(), gcp)
		require.NoError(t, err)
		assert.Equal(t, "ya29.minted", token)
	}

	assert.Equal(t, int64(1), calls.Load(),
		"a valid access token must be reused instead of signing a new JWT on every request")
}

func TestTokenCacheIsolatesServiceAccounts(t *testing.T) {
	var calls atomic.Int64
	server := tokenEndpoint(t, &calls)
	cache := newTokenCache()

	for _, email := range []string{"one@careplus-poc.iam.gserviceaccount.com", "two@careplus-poc.iam.gserviceaccount.com"} {
		_, err := cache.token(context.Background(), &providers.GCP{
			ServiceAccountJSON: serviceAccountJSON(t, server.URL, email),
		})
		require.NoError(t, err)
	}

	assert.Equal(t, int64(2), calls.Load(), "each service account needs its own token")
}

func TestTokenCacheConcurrentCallers(t *testing.T) {
	var calls atomic.Int64
	server := tokenEndpoint(t, &calls)
	cache := newTokenCache()
	gcp := &providers.GCP{ServiceAccountJSON: serviceAccountJSON(t, server.URL, "sa@careplus-poc.iam.gserviceaccount.com")}

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := cache.token(context.Background(), gcp)
			assert.NoError(t, err)
			assert.Equal(t, "ya29.minted", token)
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(1), calls.Load(), "concurrent requests must share a single token exchange")
}

func TestTokenCacheErrors(t *testing.T) {
	var calls atomic.Int64
	server := tokenEndpoint(t, &calls)

	rejecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`)
	}))
	t.Cleanup(rejecting.Close)

	tests := []struct {
		name        string
		gcp         *providers.GCP
		cancel      bool
		errContains string
	}{
		{name: "nil credentials", gcp: nil, errContains: "required"},
		{name: "empty json", gcp: &providers.GCP{}, errContains: "required"},
		{
			name:        "malformed json",
			gcp:         &providers.GCP{ServiceAccountJSON: "{not-json"},
			errContains: "parsing gcp service account credentials",
		},
		{
			name: "external account config is rejected",
			gcp: &providers.GCP{ServiceAccountJSON: `{"type":"external_account","audience":"//iam.googleapis.com/x",` +
				`"token_url":"https://sts.googleapis.com/v1/token","credential_source":{"executable":{"command":"/bin/sh -c id"}}}`},
			errContains: "parsing gcp service account credentials",
		},
		{
			name:        "google rejects the assertion",
			gcp:         &providers.GCP{ServiceAccountJSON: serviceAccountJSON(t, rejecting.URL, "sa@careplus-poc.iam.gserviceaccount.com")},
			errContains: "exchanging gcp service account for an access token",
		},
		{
			name:        "cancelled context",
			gcp:         &providers.GCP{ServiceAccountJSON: serviceAccountJSON(t, server.URL, "sa@careplus-poc.iam.gserviceaccount.com")},
			cancel:      true,
			errContains: "context canceled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancel {
				cancel()
			}

			_, err := newTokenCache().token(ctx, tt.gcp)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestBearerTokenWrapsCredentialFailures(t *testing.T) {
	c := &client{
		tokenSource: func(context.Context, *providers.GCP) (string, error) {
			return "", fmt.Errorf("invalid_grant")
		},
	}

	_, err := c.bearerToken(context.Background(), &providers.Config{
		Credentials: providers.Credentials{GCP: &providers.GCP{ServiceAccountJSON: `{"type":"service_account"}`}},
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, registry.ErrCredentialAcquisition,
		"credential failures must be terminal so the proxy does not retry or fall back")
}

func TestBearerTokenSources(t *testing.T) {
	t.Run("service account takes precedence over api key", func(t *testing.T) {
		c := &client{
			tokenSource: func(context.Context, *providers.GCP) (string, error) {
				return "minted", nil
			},
		}

		token, err := c.bearerToken(context.Background(), &providers.Config{
			Credentials: providers.Credentials{
				ApiKey: "stale-manual-token",
				GCP:    &providers.GCP{ServiceAccountJSON: `{"type":"service_account"}`},
			},
		})

		require.NoError(t, err)
		assert.Equal(t, "minted", token)
	})

	t.Run("pre-minted bearer token is used verbatim", func(t *testing.T) {
		token, err := (&client{}).bearerToken(context.Background(), &providers.Config{
			Credentials: providers.Credentials{ApiKey: "ya29.manual"},
		})

		require.NoError(t, err)
		assert.Equal(t, "ya29.manual", token)
	})

	t.Run("no credentials at all", func(t *testing.T) {
		_, err := (&client{}).bearerToken(context.Background(), &providers.Config{})

		require.Error(t, err)
		assert.ErrorIs(t, err, registry.ErrCredentialAcquisition)
	})
}
