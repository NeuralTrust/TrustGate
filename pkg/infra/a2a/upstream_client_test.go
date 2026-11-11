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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard/netguardtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpstreamClientSendsExactlyTheHeaderGiven(t *testing.T) {
	netguardtest.Allow(t)
	var got http.Header
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		body, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	res, err := NewUpstreamClient().Post(context.Background(), srv.URL, http.Header{"X-Tenant": {"acme"}}, []byte(`{"a":1}`))
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
	assert.Equal(t, "acme", got.Get("X-Tenant"))
	assert.Empty(t, got.Get("Authorization"))
	assert.JSONEq(t, `{"a":1}`, string(body))
}

func TestUpstreamClientRefusesPrivateAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	_, err := NewUpstreamClient().Post(context.Background(), srv.URL, http.Header{}, nil)
	require.Error(t, err)
}
