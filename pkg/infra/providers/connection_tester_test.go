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

package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClassifyProbeStatus(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		wantOK    bool
		wantStage ProbeStage
	}{
		{name: "200 ok", status: http.StatusOK, wantOK: true, wantStage: StageAuthentication},
		{name: "204 ok", status: http.StatusNoContent, wantOK: true, wantStage: StageAuthentication},
		{name: "401 auth", status: http.StatusUnauthorized, wantOK: false, wantStage: StageAuthentication},
		{name: "403 auth", status: http.StatusForbidden, wantOK: false, wantStage: StageAuthentication},
		{name: "404 provider", status: http.StatusNotFound, wantOK: false, wantStage: StageProvider},
		{name: "500 provider", status: http.StatusInternalServerError, wantOK: false, wantStage: StageProvider},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyProbeStatus(tt.status)
			assert.Equal(t, tt.wantOK, got.OK)
			assert.Equal(t, tt.wantStage, got.Stage)
			assert.Equal(t, tt.status, got.StatusCode)
		})
	}
}

func TestClassifyProbeStatusForProvider_GoogleBadRequestIsAuthentication(t *testing.T) {
	got := ClassifyProbeStatusForProvider(ProviderGoogle, http.StatusBadRequest)

	assert.False(t, got.OK)
	assert.Equal(t, StageAuthentication, got.Stage)
	assert.Equal(t, http.StatusBadRequest, got.StatusCode)
	assert.Contains(t, got.Message, "provider rejected the credentials")
}

func TestRunHTTPProbe_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer sk-test", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer sk-test")

	got := RunHTTPProbe("test-ok", req)
	assert.True(t, got.OK)
	assert.Equal(t, StageAuthentication, got.Stage)
}

func TestRunHTTPProbe_AuthFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	got := RunHTTPProbe("test-auth", req)
	assert.False(t, got.OK)
	assert.Equal(t, StageAuthentication, got.Stage)
	assert.Equal(t, http.StatusUnauthorized, got.StatusCode)
}

func TestRunHTTPProbe_Unreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	require.NoError(t, err)

	got := RunHTTPProbe("test-unreachable", req)
	assert.False(t, got.OK)
	assert.Equal(t, StageConnectivity, got.Stage)
	assert.NotEmpty(t, got.Message)
}
