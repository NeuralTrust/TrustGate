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

package introspection_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/auth/introspection"
)

func stubEndpoint(t *testing.T, calls *atomic.Int64, response map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil || r.PostForm.Get("token") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestValidator_ActiveToken(t *testing.T) {
	var calls atomic.Int64
	srv := stubEndpoint(t, &calls, map[string]any{
		"active": true,
		"sub":    "service-7",
		"scope":  "mcp.read",
		"aud":    "trustgate",
		"iss":    "https://idp.example.com",
		"exp":    time.Now().Add(time.Hour).Unix(),
	})
	v := introspection.NewValidator(nil)
	cfg := &authdomain.OAuth2Config{
		Issuer:           "https://idp.example.com",
		IntrospectionURL: srv.URL,
		Audiences:        []string{"trustgate"},
		ClientID:         "client",
		ClientSecret:     "secret",
	}

	principal, err := v.Validate(context.Background(), "opaque-token", cfg)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if principal.Subject != "service-7" || principal.Method != identity.MethodIntrospection {
		t.Fatalf("unexpected principal: %+v", principal)
	}
}

func TestValidator_CachesUntilExpiry(t *testing.T) {
	var calls atomic.Int64
	srv := stubEndpoint(t, &calls, map[string]any{
		"active": true,
		"sub":    "service-7",
		"exp":    time.Now().Add(time.Hour).Unix(),
	})
	v := introspection.NewValidator(nil)
	cfg := &authdomain.OAuth2Config{Issuer: "x", IntrospectionURL: srv.URL}

	for range 3 {
		if _, err := v.Validate(context.Background(), "opaque-token", cfg); err != nil {
			t.Fatalf("validate: %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected 1 IdP call (cached), got %d", got)
	}
}

func TestValidator_RejectsInactiveToken(t *testing.T) {
	var calls atomic.Int64
	srv := stubEndpoint(t, &calls, map[string]any{"active": false})
	v := introspection.NewValidator(nil)
	cfg := &authdomain.OAuth2Config{Issuer: "x", IntrospectionURL: srv.URL}

	if _, err := v.Validate(context.Background(), "revoked", cfg); err == nil {
		t.Fatal("expected inactive rejection")
	}
}

func TestValidator_RejectsAudienceMismatch(t *testing.T) {
	var calls atomic.Int64
	srv := stubEndpoint(t, &calls, map[string]any{
		"active": true, "sub": "s", "aud": []string{"other"},
	})
	v := introspection.NewValidator(nil)
	cfg := &authdomain.OAuth2Config{Issuer: "x", IntrospectionURL: srv.URL, Audiences: []string{"trustgate"}}

	if _, err := v.Validate(context.Background(), "tok", cfg); err == nil {
		t.Fatal("expected audience rejection")
	}
}

func TestValidator_RejectsMissingScopes(t *testing.T) {
	var calls atomic.Int64
	srv := stubEndpoint(t, &calls, map[string]any{
		"active": true, "sub": "s", "scope": "mcp.read",
	})
	v := introspection.NewValidator(nil)
	cfg := &authdomain.OAuth2Config{Issuer: "x", IntrospectionURL: srv.URL, RequiredScopes: []string{"mcp.admin"}}

	if _, err := v.Validate(context.Background(), "tok", cfg); err == nil {
		t.Fatal("expected scope rejection")
	}
}
