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

package topicguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/topic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeTokens struct {
	invalidated atomic.Int32
	configured  bool
}

func (f *fakeTokens) Configured() bool       { return f.configured }
func (f *fakeTokens) Invalidate()            { f.invalidated.Add(1) }
func (f *fakeTokens) Token() (string, error) { return "tok", nil }

type fakeTopicGuard struct {
	mu           sync.Mutex
	classifyHits int
	configHits   int
	lastBody     map[string]any
	lastToken    string
	classify     http.HandlerFunc
	config       http.HandlerFunc
}

func (f *fakeTopicGuard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.lastToken = r.Header.Get("token")
	f.mu.Unlock()
	switch r.URL.Path {
	case classifyPath:
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		f.mu.Lock()
		f.classifyHits++
		f.lastBody = body
		handler := f.classify
		f.mu.Unlock()
		if handler == nil {
			handler = echoScores
		}
		handler(w, r)
	case configPath:
		f.mu.Lock()
		f.configHits++
		handler := f.config
		f.mu.Unlock()
		if handler == nil {
			handler = func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"name":"topic-guard","revision":"r7","candidate_revision":"cal3"}`))
			}
		}
		handler(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeTopicGuard) hits() (classify, config int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.classifyHits, f.configHits
}

func echoScores(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte(`[
	  {"topic_scores": {"legal": {"topic": "legal", "probability": 0.1, "blocked": false, "raw_score": 0.1},
	                    "billing": {"topic": "billing", "probability": 0.92, "blocked": true, "raw_score": 0.9}},
	   "is_blocked": true, "blocked_topics": ["billing"], "n_windows": 1, "warnings": []},
	  {"topic_scores": {"legal": {"topic": "legal", "probability": 0.8, "blocked": true, "raw_score": 0.8},
	                    "billing": {"topic": "billing", "probability": 0.05, "blocked": false, "raw_score": 0.05}},
	   "is_blocked": true, "blocked_topics": ["legal"], "n_windows": 2, "warnings": []}
	]`))
}

var catalog = []topic.Topic{
	{Name: "billing", Definition: "refunds and invoices"},
	{Name: "legal", Definition: "contracts and terms"},
}

func newTestClient(t *testing.T, fake *fakeTopicGuard) (*Client, *fakeTokens) {
	t.Helper()
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	tokens := &fakeTokens{configured: true}
	return NewClient(srv.URL+"/", tokens, time.Second), tokens
}

func TestClassify_RoundTrip(t *testing.T) {
	t.Parallel()
	fake := &fakeTopicGuard{}
	client, _ := newTestClient(t, fake)

	got, err := client.Classify(context.Background(), catalog, nil, []string{"refund please", "can I end the contract"})
	require.NoError(t, err)
	require.Len(t, got, 2)

	assert.Equal(t, []topic.Score{
		{Topic: "billing", Probability: 0.92, Matched: true},
		{Topic: "legal", Probability: 0.1, Matched: false},
	}, got[0].Scores)
	assert.Equal(t, []string{"billing"}, got[0].Matched)
	assert.Equal(t, 1, got[0].Windows)
	assert.Equal(t, []string{"legal"}, got[1].Matched)
	assert.Equal(t, 2, got[1].Windows)
	assert.Equal(t, "topic-guard@r7+cal3", got[0].ModelVersion)

	fake.mu.Lock()
	defer fake.mu.Unlock()
	assert.Equal(t, "tok", fake.lastToken)
	assert.Equal(t, []any{"refund please", "can I end the contract"}, fake.lastBody["input"])
	assert.NotContains(t, fake.lastBody, "threshold", "an unset threshold must defer to the firewall's operating point")
	assert.Len(t, fake.lastBody["topics"], 2)
}

func TestClassify_SendsThresholdWhenSet(t *testing.T) {
	t.Parallel()
	fake := &fakeTopicGuard{}
	client, _ := newTestClient(t, fake)
	threshold := 0.35

	_, err := client.Classify(context.Background(), catalog, &threshold, []string{"a", "b"})
	require.NoError(t, err)

	fake.mu.Lock()
	defer fake.mu.Unlock()
	assert.InDelta(t, 0.35, fake.lastBody["threshold"], 1e-9)
}

func TestClassify_Errors(t *testing.T) {
	t.Parallel()

	status := func(code int, header, value string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			if header != "" {
				w.Header().Set(header, value)
			}
			w.WriteHeader(code)
		}
	}

	t.Run("503 is backpressure with the advertised wait", func(t *testing.T) {
		t.Parallel()
		client, tokens := newTestClient(t, &fakeTopicGuard{classify: status(http.StatusServiceUnavailable, "Retry-After", "3")})
		_, err := client.Classify(context.Background(), catalog, nil, []string{"a"})
		var bp *topic.BackpressureError
		require.ErrorAs(t, err, &bp)
		assert.Equal(t, 3*time.Second, bp.RetryAfter)
		assert.Zero(t, tokens.invalidated.Load())
	})

	t.Run("503 without Retry-After waits the default", func(t *testing.T) {
		t.Parallel()
		client, _ := newTestClient(t, &fakeTopicGuard{classify: status(http.StatusServiceUnavailable, "", "")})
		_, err := client.Classify(context.Background(), catalog, nil, []string{"a"})
		var bp *topic.BackpressureError
		require.ErrorAs(t, err, &bp)
		assert.Equal(t, defaultRetryAfter, bp.RetryAfter)
	})

	t.Run("401 invalidates the token", func(t *testing.T) {
		t.Parallel()
		client, tokens := newTestClient(t, &fakeTopicGuard{classify: status(http.StatusUnauthorized, "", "")})
		_, err := client.Classify(context.Background(), catalog, nil, []string{"a"})
		require.ErrorIs(t, err, topic.ErrClassifierUnauthorized)
		assert.Equal(t, int32(1), tokens.invalidated.Load())
	})

	t.Run("422 is a plain error, not backpressure", func(t *testing.T) {
		t.Parallel()
		client, _ := newTestClient(t, &fakeTopicGuard{classify: status(http.StatusUnprocessableEntity, "", "")})
		_, err := client.Classify(context.Background(), catalog, nil, []string{"a"})
		require.Error(t, err)
		var bp *topic.BackpressureError
		assert.False(t, errors.As(err, &bp))
	})

	t.Run("malformed body", func(t *testing.T) {
		t.Parallel()
		client, _ := newTestClient(t, &fakeTopicGuard{classify: func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"not": "a list"`))
		}})
		_, err := client.Classify(context.Background(), catalog, nil, []string{"a"})
		require.Error(t, err)
	})

	t.Run("fewer results than texts", func(t *testing.T) {
		t.Parallel()
		client, _ := newTestClient(t, &fakeTopicGuard{})
		_, err := client.Classify(context.Background(), catalog, nil, []string{"a", "b", "c"})
		require.ErrorContains(t, err, "got 2 results for 3 texts")
	})

	t.Run("timeout", func(t *testing.T) {
		t.Parallel()
		release := make(chan struct{})
		t.Cleanup(func() { close(release) })
		client, _ := newTestClient(t, &fakeTopicGuard{classify: func(_ http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}})
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err := client.Classify(ctx, catalog, nil, []string{"a"})
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
}

func TestClassify_LocalGuards(t *testing.T) {
	t.Parallel()
	fake := &fakeTopicGuard{}
	client, _ := newTestClient(t, fake)

	got, err := client.Classify(context.Background(), catalog, nil, nil)
	require.NoError(t, err)
	assert.Nil(t, got)

	tooMany := make([]string, topic.MaxBatchTexts+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("text %d", i)
	}
	_, err = client.Classify(context.Background(), catalog, nil, tooMany)
	require.ErrorContains(t, err, "batch limit")

	classifyHits, _ := fake.hits()
	assert.Zero(t, classifyHits, "neither guard may reach topic-guard")
}

func TestClient_NotConfigured(t *testing.T) {
	t.Parallel()
	for name, client := range map[string]*Client{
		"no base url":    NewClient("", &fakeTokens{configured: true}, 0),
		"no secret":      NewClient("http://firewall", &fakeTokens{configured: false}, 0),
		"no token store": NewClient("http://firewall", nil, 0),
	} {
		_, err := client.Classify(context.Background(), catalog, nil, []string{"a"})
		require.ErrorIs(t, err, topic.ErrClassifierNotConfigured, name)
		_, err = client.ModelVersion(context.Background())
		require.ErrorIs(t, err, topic.ErrClassifierNotConfigured, name)
	}
}

func TestModelVersion_CachesAndRefreshes(t *testing.T) {
	t.Parallel()
	fake := &fakeTopicGuard{}
	client, _ := newTestClient(t, fake)
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	client.now = func() time.Time { return now }

	for range 3 {
		v, err := client.ModelVersion(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "topic-guard@r7+cal3", v)
	}
	_, configHits := fake.hits()
	assert.Equal(t, 1, configHits, "the version must be cached")

	now = now.Add(modelVersionTTL + time.Second)
	fake.mu.Lock()
	fake.config = func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"name":"topic-guard","revision":"r8"}`))
	}
	fake.mu.Unlock()
	v, err := client.ModelVersion(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "topic-guard@r8", v, "a redeploy must be picked up once the cache expires")
}

func TestModelVersion_FailureKeepsLastKnownAndRetriesSooner(t *testing.T) {
	t.Parallel()
	fake := &fakeTopicGuard{}
	client, _ := newTestClient(t, fake)
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	client.now = func() time.Time { return now }

	_, err := client.ModelVersion(context.Background())
	require.NoError(t, err)

	now = now.Add(modelVersionTTL + time.Second)
	fake.mu.Lock()
	fake.config = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }
	fake.mu.Unlock()

	v, err := client.ModelVersion(context.Background())
	require.Error(t, err)
	assert.Equal(t, "topic-guard@r7+cal3", v, "a failed refresh must keep the last known version")

	_, before := fake.hits()
	now = now.Add(modelVersionRetry - time.Second)
	_, _ = client.ModelVersion(context.Background())
	_, during := fake.hits()
	assert.Equal(t, before, during, "within the retry window the failure is not re-fetched")

	now = now.Add(2 * time.Second)
	_, _ = client.ModelVersion(context.Background())
	_, after := fake.hits()
	assert.Equal(t, during+1, after, "after the retry window it asks again")
}
