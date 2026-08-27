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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestProviderClient_SlackTokenResponse(t *testing.T) {
	t.Parallel()

	t.Run("missing expires_in remains unknown", func(t *testing.T) {
		t.Parallel()
		srv := tokenServer(t, map[string]any{
			"ok":            true,
			"access_token":  "access",
			"refresh_token": "refresh",
			"token_type":    "user",
		})
		token, err := NewProviderClient(srv.Client()).Refresh(
			context.Background(),
			&registrydomain.MCPAuth{ClientID: "id", TokenURL: srv.URL},
			"refresh",
		)
		if err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if !token.ExpiresAt.IsZero() {
			t.Fatalf("ExpiresAt = %v, want unknown zero value", token.ExpiresAt)
		}
	})

	t.Run("string expires_in is accepted", func(t *testing.T) {
		t.Parallel()
		srv := tokenServer(t, map[string]any{
			"ok":           true,
			"access_token": "access",
			"token_type":   "user",
			"expires_in":   "3600",
		})
		before := time.Now().Add(59 * time.Minute)
		token, err := NewProviderClient(srv.Client()).Refresh(
			context.Background(),
			&registrydomain.MCPAuth{ClientID: "id", TokenURL: srv.URL},
			"refresh",
		)
		if err != nil {
			t.Fatalf("Refresh: %v", err)
		}
		if token.ExpiresAt.Before(before) || token.ExpiresAt.After(time.Now().Add(61*time.Minute)) {
			t.Fatalf("ExpiresAt = %v, want approximately one hour", token.ExpiresAt)
		}
	})

	t.Run("invalid refresh token requires consent", func(t *testing.T) {
		t.Parallel()
		srv := tokenServer(t, map[string]any{
			"ok":    false,
			"error": "invalid_refresh_token",
		})
		_, err := NewProviderClient(srv.Client()).Refresh(
			context.Background(),
			&registrydomain.MCPAuth{ClientID: "id", TokenURL: srv.URL},
			"refresh",
		)
		if !errors.Is(err, appoauth.ErrInvalidGrant) {
			t.Fatalf("error = %v, want ErrInvalidGrant", err)
		}
	})
}

func tokenServer(t *testing.T, response map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(srv.Close)
	return srv
}
