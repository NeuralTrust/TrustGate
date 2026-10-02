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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/common/gcpkey"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingTransport answers requests for Google's real token endpoint from a
// local stub and passes every other request through untouched, so a request
// that escaped the pin would reach the attacker server for real.
type recordingTransport struct {
	google *httptest.Server
	mu     sync.Mutex
	urls   []string
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.urls = append(r.urls, req.URL.String())
	r.mu.Unlock()
	if req.URL.String() == gcpkey.TokenURL {
		clone := req.Clone(req.Context())
		clone.URL.Scheme = "http"
		clone.URL.Host = r.google.Listener.Addr().String()
		return http.DefaultTransport.RoundTrip(clone)
	}
	return http.DefaultTransport.RoundTrip(req)
}

// A tenant-supplied key must never choose where the signed assertion is sent.
func TestTokenCachePinsTokenEndpoint(t *testing.T) {
	var googleCalls, attackerCalls atomic.Int64
	google := tokenEndpoint(t, &googleCalls)
	attacker := tokenEndpoint(t, &attackerCalls)

	tests := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{name: "hostile token_uri", mutate: func(m map[string]string) { m["token_uri"] = attacker.URL }},
		{name: "absent token_uri", mutate: func(m map[string]string) { delete(m, "token_uri") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attackerCalls.Store(0)
			googleCalls.Store(0)
			var m map[string]string
			require.NoError(t, json.Unmarshal([]byte(serviceAccountJSON(t, gcpkey.TokenURL, "sa@careplus-poc.iam.gserviceaccount.com")), &m))
			tt.mutate(m)
			raw, err := json.Marshal(m)
			require.NoError(t, err)

			rec := &recordingTransport{google: google}
			cache := newTokenCache()
			cache.httpClient = &http.Client{Transport: rec}

			token, err := cache.token(context.Background(), &providers.GCP{ServiceAccountJSON: string(raw)})

			require.NoError(t, err)
			assert.Equal(t, "ya29.minted", token)
			assert.Zero(t, attackerCalls.Load(), "the gateway must never contact a token_uri taken from the key")
			assert.Equal(t, []string{gcpkey.TokenURL}, rec.urls, "token request must go to the pinned Google endpoint")
			assert.Equal(t, int64(1), googleCalls.Load())
		})
	}
}

func TestTokenCacheDoesNotLeakAttackerAudienceIntoAssertion(t *testing.T) {
	var googleCalls atomic.Int64
	var assertion atomic.Value
	google := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		googleCalls.Add(1)
		_ = r.ParseForm()
		assertion.Store(r.PostForm.Get("assertion"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"ya29.minted","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(google.Close)

	var m map[string]string
	require.NoError(t, json.Unmarshal([]byte(serviceAccountJSON(t, gcpkey.TokenURL, "sa@careplus-poc.iam.gserviceaccount.com")), &m))
	m["audience"] = "http://attacker.invalid/"
	raw, err := json.Marshal(m)
	require.NoError(t, err)

	cache := newTokenCache()
	cache.httpClient = &http.Client{Transport: &recordingTransport{google: google}}
	_, err = cache.token(context.Background(), &providers.GCP{ServiceAccountJSON: string(raw)})
	require.NoError(t, err)

	got, _ := assertion.Load().(string)
	parts := strings.Split(got, ".")
	require.Len(t, parts, 3)
	claims, err := decodeSegment(parts[1])
	require.NoError(t, err)
	assert.Contains(t, string(claims), gcpkey.TokenURL)
	assert.NotContains(t, string(claims), "attacker.invalid")
}

func decodeSegment(seg string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(seg)
}
