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

package a2a

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard/netguardtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testCard = `{"name":"Travel planner"}`

func cardServer(t *testing.T, routes map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := routes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestResolveProbesInOrder(t *testing.T) {
	netguardtest.Allow(t)
	srv := cardServer(t, map[string]string{
		"/agents/travel/.well-known/agent.json": testCard,
		"/agents/travel/agentCard/v1.0":         `{"name":"later"}`,
	})
	got, err := NewCardFetcher(nil).Resolve(context.Background(), srv.URL+"/agents/travel/", nil)
	require.NoError(t, err)
	assert.Equal(t, srv.URL+"/agents/travel/.well-known/agent.json", got.URL)
	assert.JSONEq(t, testCard, string(got.Card))
}

func TestResolveReadsACardURLDirectly(t *testing.T) {
	netguardtest.Allow(t)
	srv := cardServer(t, map[string]string{"/card.json": testCard})
	got, err := NewCardFetcher(nil).Resolve(context.Background(), srv.URL+"/card.json", nil)
	require.NoError(t, err)
	assert.Equal(t, srv.URL+"/card.json", got.URL)
}

func TestResolveReportsEveryTriedURL(t *testing.T) {
	netguardtest.Allow(t)
	srv := cardServer(t, map[string]string{"/.well-known/agent-card.json": `["not","an","object"]`})
	_, err := NewCardFetcher(nil).Resolve(context.Background(), srv.URL, nil)
	require.ErrorIs(t, err, domain.ErrAgentCardUnavailable)
	for _, p := range cardProbePaths {
		assert.Contains(t, err.Error(), srv.URL+p)
	}
	assert.Contains(t, err.Error(), "not a JSON object")
}

func TestResolveRefusesPrivateAddresses(t *testing.T) {
	netguardtest.Deny(t)
	srv, hits := netguardtest.Hostile(t, nil)
	_, err := NewCardFetcher(nil).Resolve(context.Background(), srv.URL, nil)
	require.ErrorIs(t, err, domain.ErrAgentCardUnavailable)
	assert.Zero(t, hits.Load())
}

func TestFetchRefusesOversizedCards(t *testing.T) {
	netguardtest.Allow(t)
	big := `{"name":"x","pad":"` + strings.Repeat("a", maxCardBytes) + `"}`
	srv := cardServer(t, map[string]string{"/card.json": big})
	_, err := NewCardFetcher(nil).Fetch(context.Background(), srv.URL+"/card.json", nil)
	require.ErrorIs(t, err, domain.ErrAgentCardUnavailable)
	assert.Contains(t, err.Error(), "exceeds")
}

func TestFetchWithAuthorizerSendsCredentialAndRefusesRedirects(t *testing.T) {
	netguardtest.Allow(t)
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/moved.json" {
			http.Redirect(w, r, "/card.json", http.StatusFound)
			return
		}
		seen = r.Header.Get("X-Key")
		_, _ = w.Write([]byte(testCard))
	}))
	t.Cleanup(srv.Close)
	authorize := func(r *http.Request) error {
		r.Header.Set("X-Key", "secret")
		return nil
	}
	f := NewCardFetcher(nil)

	_, err := f.Fetch(context.Background(), srv.URL+"/card.json", authorize)
	require.NoError(t, err)
	assert.Equal(t, "secret", seen)

	_, err = f.Fetch(context.Background(), srv.URL+"/moved.json", authorize)
	require.ErrorIs(t, err, domain.ErrAgentCardUnavailable)
	assert.Contains(t, err.Error(), "status 302")
}

func TestFetchRefusesHTTPWithoutPrivateNetworks(t *testing.T) {
	netguardtest.Deny(t)
	_, err := NewCardFetcher(nil).Fetch(context.Background(), "http://agent.example.com/card.json", nil)
	require.ErrorIs(t, err, domain.ErrAgentCardUnavailable)
	assert.Contains(t, err.Error(), "https")
}

func TestFetchReportsWhatTheRefusalSays(t *testing.T) {
	netguardtest.Allow(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Amzn-Errortype", "ValidationException:http://internal.amazon.com/coral/com.amazon.bedrock.agentcore/")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"Agent runtime is not configured for A2A"}`))
	}))
	t.Cleanup(srv.Close)

	_, err := NewCardFetcher(nil).Fetch(context.Background(), srv.URL+"/card.json", nil)
	require.ErrorIs(t, err, domain.ErrAgentCardUnavailable)
	assert.Contains(t, err.Error(), "status 400: ValidationException Agent runtime is not configured for A2A")
}

func TestProbeAcceptsAnAgentAndSaysWhyAnythingElseIsNot(t *testing.T) {
	netguardtest.Allow(t)
	var got struct {
		method, version, key string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var call struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&call)
		got.method, got.version, got.key = call.Method, r.Header.Get("A2A-Version"), r.Header.Get("X-Key")
		switch r.URL.Path {
		case "/agent":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"trustgate-probe","error":{"code":-32001,"message":"Task not found"}}`))
		case "/locked":
			w.WriteHeader(http.StatusUnauthorized)
		case "/moved":
			http.Redirect(w, r, "/agent", http.StatusFound)
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte("<!DOCTYPE html><title>405</title>"))
		}
	}))
	t.Cleanup(srv.Close)
	f := NewCardFetcher(nil)
	authorize := func(r *http.Request) error {
		r.Header.Set("X-Key", "secret")
		return nil
	}

	require.NoError(t, f.Probe(context.Background(), srv.URL+"/agent", domain.A2AVersion10, authorize))
	assert.Equal(t, "GetTask", got.method)
	assert.Equal(t, "1.0", got.version)
	assert.Equal(t, "secret", got.key)

	require.NoError(t, f.Probe(context.Background(), srv.URL+"/agent", domain.A2AVersion03, nil))
	assert.Equal(t, "tasks/get", got.method)

	err := f.Probe(context.Background(), srv.URL+"/", domain.A2AVersion03, nil)
	require.ErrorIs(t, err, domain.ErrAgentEndpointUnavailable)
	assert.Contains(t, err.Error(), "did not answer A2A JSON-RPC: HTTP 405 (text/html)")

	err = f.Probe(context.Background(), srv.URL+"/locked", domain.A2AVersion03, nil)
	require.ErrorIs(t, err, domain.ErrAgentEndpointUnavailable)
	assert.Contains(t, err.Error(), "refused the agent's credential: HTTP 401")

	err = f.Probe(context.Background(), srv.URL+"/moved", domain.A2AVersion03, authorize)
	require.ErrorIs(t, err, domain.ErrAgentEndpointUnavailable, "a redirect is not followed")
	assert.Contains(t, err.Error(), "HTTP 302")
}
