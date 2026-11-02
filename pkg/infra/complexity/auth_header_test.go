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

package complexity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/infra/firewall"
)

func firewallStub(t *testing.T, check func(*http.Request) int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var tokenCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/token" {
			n := tokenCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": fmt.Sprintf("access-%d", n),
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
			return
		}
		if status := check(r); status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_ = json.NewEncoder(w).Encode(scoreResponse{RawScore: newFloat(0.5), Revision: testRevision})
	}))
	t.Cleanup(srv.Close)
	return srv, &tokenCalls
}

func TestClientSendsBearerWithOAuth(t *testing.T) {
	t.Parallel()
	srv, tokenCalls := firewallStub(t, func(r *http.Request) int {
		assert.Equal(t, "Bearer access-1", r.Header.Get("Authorization"))
		assert.Empty(t, r.Header.Get("token"))
		return http.StatusOK
	})
	c := NewClient(srv.URL, firewall.NewOAuthTokenSource(srv.URL, "client", "secret", nil), time.Second, testRevision)
	for range 2 {
		score, err := c.ScoreSR1(context.Background(), "hello", "tenant")
		require.NoError(t, err)
		assert.InDelta(t, 0.5, score, 1e-9)
	}
	assert.EqualValues(t, 1, tokenCalls.Load())
}

func TestClientSendsTokenHeaderWithLegacySecret(t *testing.T) {
	t.Parallel()
	srv, tokenCalls := firewallStub(t, func(r *http.Request) int {
		assert.NotEmpty(t, r.Header.Get("token"))
		assert.Empty(t, r.Header.Get("Authorization"))
		return http.StatusOK
	})
	c := NewClient(srv.URL, firewall.NewTokenProvider("legacy-secret"), time.Second, testRevision)
	_, err := c.ScoreSR1(context.Background(), "hello", "tenant")
	require.NoError(t, err)
	assert.Zero(t, tokenCalls.Load())
}

func TestClientBacksOffAfterFreshOAuthTokenRejected(t *testing.T) {
	t.Parallel()
	var scoreCalls atomic.Int32
	srv, tokenCalls := firewallStub(t, func(r *http.Request) int {
		if scoreCalls.Add(1) == 1 {
			return http.StatusUnauthorized
		}
		assert.Equal(t, "Bearer access-2", r.Header.Get("Authorization"))
		return http.StatusOK
	})
	src := firewall.NewOAuthTokenSource(srv.URL, "client", "secret", nil)
	c := NewClient(srv.URL, src, time.Second, testRevision)

	_, err := c.ScoreSR1(context.Background(), "hello", "")
	require.ErrorIs(t, err, ErrUnauthorized)
	_, err = c.ScoreSR1(context.Background(), "hello", "")
	require.ErrorIs(t, err, firewall.ErrTokenRejected)
	assert.EqualValues(t, 1, tokenCalls.Load())
}

func TestClientFailsWithUnusableCredential(t *testing.T) {
	t.Parallel()
	srv, _ := firewallStub(t, func(*http.Request) int {
		t.Error("the firewall must not be called with an unusable credential")
		return http.StatusOK
	})
	cause := errors.New("FIREWALL_JWT has expired")
	c := NewClient(srv.URL, firewall.NewUnusableSource(cause, nil), time.Second, testRevision)
	require.True(t, c.Configured())
	_, err := c.ScoreSR1(context.Background(), "hello", "")
	require.ErrorIs(t, err, cause)
}

func TestClientWithUnusableCredentialAndNoBaseURLIsUnconfigured(t *testing.T) {
	t.Parallel()
	cause := errors.New("FIREWALL_JWT is malformed")
	c := NewClient("", firewall.NewUnusableSource(cause, nil), time.Second, testRevision)
	assert.False(t, c.Configured())
	_, err := c.ScoreSR1(context.Background(), "hello", "")
	require.ErrorIs(t, err, ErrNotConfigured)
}
