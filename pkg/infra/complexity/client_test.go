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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testRevision = "9619f81d9db28141fc1cc0a3833c8446260ce603"

func newFloat(value float64) *float64 { return &value }

type tokenProviderStub struct {
	configured bool
	token      string
	err        error
	invalidate func()
}

func (s tokenProviderStub) Configured() bool       { return s.configured }
func (s tokenProviderStub) Token() (string, error) { return s.token, s.err }
func (s tokenProviderStub) Invalidate() {
	if s.invalidate != nil {
		s.invalidate()
	}
}

func TestClient_Configured(t *testing.T) {
	t.Parallel()
	configured := tokenProviderStub{configured: true, token: "tok"}
	assert.False(t, NewClient("", configured, 0, testRevision).Configured())
	assert.False(t, NewClient("http://x", nil, 0, testRevision).Configured())
	assert.False(t, NewClient("http://x", tokenProviderStub{}, 0, testRevision).Configured())
	assert.True(t, NewClient("http://x", configured, 0, testRevision).Configured())
}

func TestClient_ScoreSR1_Success(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, complexityPath, r.URL.Path)
		assert.Equal(t, "secret-token", r.Header.Get(headerToken))
		body, _ := io.ReadAll(r.Body)
		var got scoreRequest
		require.NoError(t, json.Unmarshal(body, &got))
		assert.Equal(t, "hello", got.Input)
		assert.Equal(t, "tenant_1", got.TenantID)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(scoreResponse{Score: 0.41, RawScore: newFloat(0.38), Revision: "9619f81d9db28141fc1cc0a3833c8446260ce603"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, tokenProviderStub{configured: true, token: "secret-token"}, time.Second, testRevision)
	score, err := c.ScoreSR1(context.Background(), "hello", "tenant_1")
	require.NoError(t, err)
	assert.InDelta(t, 0.38, score, 1e-9)
}

func TestClient_ScoreSR1_NotConfigured(t *testing.T) {
	t.Parallel()
	c := NewClient("", nil, time.Second, testRevision)
	_, err := c.ScoreSR1(context.Background(), "hello", "")
	assert.ErrorIs(t, err, ErrNotConfigured)
}

func TestClient_ScoreSR1_TokenError(t *testing.T) {
	t.Parallel()
	tokenErr := errors.New("mint token")
	c := NewClient("http://x", tokenProviderStub{configured: true, err: tokenErr}, time.Second, testRevision)
	_, err := c.ScoreSR1(context.Background(), "hello", "")
	assert.ErrorIs(t, err, tokenErr)
}

func TestClient_ScoreSR1_Unauthorized(t *testing.T) {
	t.Parallel()
	invalidated := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, tokenProviderStub{
		configured: true,
		token:      "bad",
		invalidate: func() { invalidated = true },
	}, time.Second, testRevision)
	_, err := c.ScoreSR1(context.Background(), "hello", "")
	assert.ErrorIs(t, err, ErrUnauthorized)
	assert.True(t, invalidated)
}

func TestClient_ScoreSR1_ServerError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, tokenProviderStub{configured: true, token: "tok"}, time.Second, testRevision)
	_, err := c.ScoreSR1(context.Background(), "hello", "")
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrUnauthorized))
}

func TestClientScoreProvenance(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, body string
		want       float64
		valid      bool
	}{
		{"configured revision", `{"revision":"another-immutable-revision","raw_score":0.7,"score":0.1}`, .7, true},
		{"zero", `{"revision":"another-immutable-revision","raw_score":0}`, 0, true},
		{"mismatch", `{"revision":"wrong","raw_score":0.3}`, 0, false},
		{"missing raw", `{"revision":"another-immutable-revision","score":0.3}`, 0, false},
		{"null raw", `{"revision":"another-immutable-revision","raw_score":null}`, 0, false},
		{"invalid raw", `{"revision":"another-immutable-revision","raw_score":"0.3"}`, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, tc.body) }))
			t.Cleanup(srv.Close)
			client := NewClient(srv.URL, tokenProviderStub{configured: true, token: "token"}, time.Second, "another-immutable-revision")
			got, err := client.ScoreSR1(context.Background(), "synthetic", "tenant")
			if tc.valid {
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			} else {
				require.Error(t, err)
			}
		})
	}
	assert.False(t, NewClient("http://x", tokenProviderStub{configured: true}, time.Second, " ").Configured())
}
