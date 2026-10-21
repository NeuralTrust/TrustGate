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
	"strings"
	"sync"
	"sync/atomic"
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
		if r.URL.Path == configPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
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

func TestClient_ScoreSR1_InputTooLargeIsTyped(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == configPath {
			_, _ = io.WriteString(w, `{"max_input_chars":null,"max_text_chars":null}`)
			return
		}
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, tokenProviderStub{configured: true, token: "tok"}, time.Second, testRevision)
	_, err := c.ScoreSR1(context.Background(), "hello", "")
	require.ErrorIs(t, err, ErrInputTooLarge)
	assert.NotContains(t, err.Error(), "hello")
}

func TestClient_LimitsRefreshNeverBlocksScoring(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	var inFlight, maxInFlight, configCalls atomic.Int32
	var inputRunes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == configPath {
			configCalls.Add(1)
			n := inFlight.Add(1)
			for {
				m := maxInFlight.Load()
				if n <= m || maxInFlight.CompareAndSwap(m, n) {
					break
				}
			}
			<-release // slow /config: held until the test releases it
			inFlight.Add(-1)
			_, _ = io.WriteString(w, `{"max_input_chars":10,"max_text_chars":null}`)
			return
		}
		var got scoreRequest
		_ = json.NewDecoder(r.Body).Decode(&got)
		inputRunes.Store(int32(len([]rune(got.Input))))
		_, _ = io.WriteString(w, `{"revision":"`+testRevision+`","raw_score":0.5}`)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, tokenProviderStub{configured: true, token: "tok"}, 5*time.Second, testRevision)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.ScoreSR1(context.Background(), "hello world, long enough", "")
			assert.NoError(t, err)
		}()
	}
	wg.Wait() // returns while /config is still blocked: scoring did not wait for it
	assert.Equal(t, int32(24), inputRunes.Load(), "defaults serve the input unchanged until /config answers")

	close(release)
	require.Eventually(t, func() bool { return !c.refreshing.Load() }, 5*time.Second, 5*time.Millisecond)
	assert.Equal(t, int32(1), configCalls.Load())
	assert.Equal(t, int32(1), maxInFlight.Load())

	_, err := c.ScoreSR1(context.Background(), "hello world, long enough", "")
	require.NoError(t, err)
	assert.Equal(t, int32(10), inputRunes.Load(), "published limit is used after the refresh")
}

func TestClient_FailingConfigKeepsDefaults(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == configPath {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, `{"revision":"`+testRevision+`","raw_score":0.5}`)
	}))
	defer srv.Close()
	c := NewClient(srv.URL, tokenProviderStub{configured: true, token: "tok"}, time.Second, testRevision)
	require.Error(t, c.RefreshLimits(context.Background()))
	assert.Equal(t, defaultMaxInputChars, c.currentLimits("tok").effective())
	long := strings.Repeat("x", defaultMaxInputChars+5)
	assert.Len(t, c.truncate("tok", long), defaultMaxInputChars)
}
