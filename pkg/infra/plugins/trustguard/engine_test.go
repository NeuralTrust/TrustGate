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

package trustguard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// tokenAnswer is how the fake /v2/token answers a gateway: a status and an OAuth error code.
type tokenAnswer struct {
	status int
	code   string
	// version is the active_version of a 200 answer; empty omits the field (a TrustGuard from before it).
	version string
}

func engineServer(t *testing.T, answers map[string]tokenAnswer, hits *int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != v2TokenPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		atomic.AddInt32(hits, 1)
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		assert.Equal(t, "platform", body["scope"])
		gw, _ := body["gateway_id"].(string)
		w.Header().Set("Content-Type", contentTypeJSON)
		a := answers[gw]
		if a.status != 0 && a.status != http.StatusOK {
			w.WriteHeader(a.status)
			_, _ = w.Write([]byte(`{"error":"` + a.code + `"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "tok-" + gw, TokenType: "Bearer", ExpiresIn: 3600, ActiveVersion: a.version})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestEngineResolver(t *testing.T) {
	t.Parallel()
	var hits int32
	srv := engineServer(t, map[string]tokenAnswer{
		"gw-v2":         {version: "v2"},
		"gw-migrated":   {version: "v1"},
		"gw-no-version": {},
		"gw-odd":        {version: "v3"},
		"gw-v1":         {status: http.StatusNotFound, code: codeUnknownGateway},
		"gw-ambiguous":  {status: http.StatusConflict, code: codeAmbiguousGateway},
		"gw-down":       {status: http.StatusInternalServerError, code: "boom"},
		"gw-denied":     {status: http.StatusUnauthorized, code: "invalid_client"},
	}, &hits)
	r := NewEngineResolver(srv.URL, "client", "secret")
	ctx := context.Background()

	assert.True(t, r.TrustGuardV2(ctx, "gw-v2"), "a token with active_version v2 means v2")
	assert.False(t, r.TrustGuardV2(ctx, "gw-migrated"), "a migrated org still active on v1 is v1")
	assert.False(t, r.TrustGuardV2(ctx, "gw-no-version"), "a token without active_version is v1")
	assert.False(t, r.TrustGuardV2(ctx, "gw-odd"), "an unknown version is v1")
	assert.False(t, r.TrustGuardV2(ctx, "gw-v1"), "unknown_gateway means v1")
	assert.False(t, r.TrustGuardV2(ctx, "gw-ambiguous"), "any other answer means v1")
	assert.False(t, r.TrustGuardV2(ctx, "gw-down"))
	assert.False(t, r.TrustGuardV2(ctx, "gw-denied"))
	assert.False(t, r.TrustGuardV2(ctx, ""), "no gateway, no question")
}

func TestEngineResolverDefaultsToV1WithoutWhatItNeeds(t *testing.T) {
	t.Parallel()
	var hits int32
	srv := engineServer(t, nil, &hits)
	assert.False(t, NewEngineResolver("", "client", "secret").TrustGuardV2(context.Background(), "gw"))
	assert.False(t, NewEngineResolver(srv.URL, "", "secret").TrustGuardV2(context.Background(), "gw"))
	assert.False(t, NewEngineResolver(srv.URL, "client", "").TrustGuardV2(context.Background(), "gw"))
	assert.Zero(t, atomic.LoadInt32(&hits), "nothing is asked without credentials or a base URL")
	var nilResolver *EngineResolver
	assert.False(t, nilResolver.TrustGuardV2(context.Background(), "gw"))
}

func TestEngineResolverUnreachableIsV1(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	assert.False(t, NewEngineResolver(url, "client", "secret").TrustGuardV2(context.Background(), "gw"))
}

func TestEngineResolverCaches(t *testing.T) {
	t.Parallel()
	var hits int32
	srv := engineServer(t, map[string]tokenAnswer{
		"gw-v2":   {version: "v2"},
		"gw-v1":   {status: http.StatusNotFound, code: codeUnknownGateway},
		"gw-down": {status: http.StatusInternalServerError, code: "boom"},
	}, &hits)
	r := NewEngineResolver(srv.URL, "client", "secret")
	now := time.Now()
	r.now = func() time.Time { return now }
	ctx := context.Background()
	asks := func() int32 { return atomic.LoadInt32(&hits) }

	for range 3 {
		assert.True(t, r.TrustGuardV2(ctx, "gw-v2"))
		assert.False(t, r.TrustGuardV2(ctx, "gw-v1"))
		assert.False(t, r.TrustGuardV2(ctx, "gw-down"))
	}
	assert.EqualValues(t, 3, asks(), "one token request per gateway, whatever the answer")

	now = now.Add(engineErrorTTL + time.Second)
	assert.False(t, r.TrustGuardV2(ctx, "gw-v1"))
	assert.False(t, r.TrustGuardV2(ctx, "gw-down"))
	assert.EqualValues(t, 4, asks(), "an error is asked again after its short TTL, unknown_gateway is not")

	now = now.Add(engineV1TTL)
	assert.False(t, r.TrustGuardV2(ctx, "gw-v1"))
	assert.EqualValues(t, 5, asks(), "unknown_gateway is asked again after its TTL")
	assert.True(t, r.TrustGuardV2(ctx, "gw-v2"))
	assert.EqualValues(t, 5, asks(), "v2 is cached until its own TTL")
	now = now.Add(engineV2TTL)
	assert.True(t, r.TrustGuardV2(ctx, "gw-v2"))
	assert.EqualValues(t, 6, asks(), "v2 is asked again after its TTL: the token cache must not hide a rollback")
}

// A cutover or rollback shows within the TTL even though the platform token itself is still valid.
func TestEngineResolverFollowsACutoverAndARollback(t *testing.T) {
	t.Parallel()
	var version atomic.Value
	version.Store("v1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentTypeJSON)
		_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "tok", TokenType: "Bearer", ExpiresIn: 3600, ActiveVersion: version.Load().(string)})
	}))
	t.Cleanup(srv.Close)
	r := NewEngineResolver(srv.URL, "client", "secret")
	now := time.Now()
	r.now = func() time.Time { return now }
	ctx := context.Background()

	assert.False(t, r.TrustGuardV2(ctx, "gw"))
	version.Store("v2")
	assert.False(t, r.TrustGuardV2(ctx, "gw"), "the v1 answer is cached")
	now = now.Add(engineV1TTL + time.Second)
	assert.True(t, r.TrustGuardV2(ctx, "gw"), "cutover seen after the TTL")
	version.Store("v1")
	now = now.Add(engineV2TTL + time.Second)
	assert.False(t, r.TrustGuardV2(ctx, "gw"), "rollback seen after the TTL")
}

func TestEngineResolverCacheIsBounded(t *testing.T) {
	t.Parallel()
	r := newEngineResolver("http://unused", newTokenManager(nil, "c", "s"))
	for i := range engineCacheMax + 50 {
		r.store(string(rune('a'+i%26))+time.Duration(i).String(), false, time.Hour)
	}
	assert.LessOrEqual(t, len(r.cache), engineCacheMax)
}
