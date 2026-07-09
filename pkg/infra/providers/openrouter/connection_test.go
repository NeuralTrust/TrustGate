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

package openrouter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
)

type openRouterProbeAt struct {
	modelsURL string
}

func (c *openRouterProbeAt) TestConnection(ctx context.Context, config *providers.Config) providers.ProbeResult {
	return providers.RunBearerGETProbe(ctx, providers.ProviderOpenRouter, c.modelsURL, config.Credentials.ApiKey)
}

func TestTestConnection_OK(t *testing.T) {
	var gotAuth, gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(srv.Close)

	got := (&openRouterProbeAt{modelsURL: srv.URL}).TestConnection(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "or-test"},
	})

	assert.True(t, got.OK)
	assert.Equal(t, providers.StageAuthentication, got.Stage)
	assert.Equal(t, "Bearer or-test", gotAuth)
	assert.Equal(t, "/", gotPath)
	assert.Equal(t, http.MethodGet, gotMethod)
}

func TestTestConnection_MissingAPIKey(t *testing.T) {
	got := NewOpenRouterClient().(interface {
		TestConnection(context.Context, *providers.Config) providers.ProbeResult
	}).TestConnection(context.Background(), &providers.Config{})

	assert.False(t, got.OK)
	assert.Equal(t, providers.StageAuthentication, got.Stage)
}

func TestTestConnection_AuthFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	got := (&openRouterProbeAt{modelsURL: srv.URL}).TestConnection(context.Background(), &providers.Config{
		Credentials: providers.Credentials{ApiKey: "or-bad"},
	})
	assert.False(t, got.OK)
}
