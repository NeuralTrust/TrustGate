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

// A forwarded client header reaches the provider; a header the provider
// client set itself is not replaced, and a request without forwarded headers
// is sent as built.
func TestForwardingTransport(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	client := NewTrustedHTTPClientPool().Get("forward-test", DefaultHTTPTimeout)
	forwarded := http.Header{}
	forwarded.Set("Traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	forwarded.Set("Anthropic-Version", "1999-01-01")
	ctx := WithForwardedHeaders(context.Background(), forwarded)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Anthropic-Version", "2023-06-01")
	resp, err := client.Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())

	assert.Equal(t, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", got.Get("Traceparent"))
	assert.Equal(t, "2023-06-01", got.Get("Anthropic-Version"), "the provider client's own header wins")
	assert.Empty(t, req.Header.Get("Traceparent"), "the caller's request must not be modified")

	plain, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, nil)
	require.NoError(t, err)
	resp, err = client.Do(plain)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	assert.Empty(t, got.Get("Traceparent"))
}
