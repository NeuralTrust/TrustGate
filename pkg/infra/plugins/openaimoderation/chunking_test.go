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

package openaimoderation

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const rateLimited = `{"error":{"message":"Rate limit reached for omni-moderation-latest in organization org-x on requests per min (RPM): Limit 3, Used 3, Requested 1.","type":"requests","param":null,"code":"rate_limit_exceeded"}}`

func benignText(kib int) string {
	return strings.Repeat("an ordinary sentence about nothing. ", kib*1024/36)
}

func TestAPhraseAcrossAChunkBoundaryIsSeenWholeInOneChunk(t *testing.T) {
	t.Parallel()
	phrase := "an unmistakably hateful phrase"
	text := benignText(100)
	cut := chunkBytes - len(phrase)/2
	text = text[:cut] + phrase + text[cut+len(phrase):]
	stub := &moderationStub{flag: func(s string) bool { return strings.Contains(s, phrase) }}
	srv := stub.server(t)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), chatRequestOf(t, text), nil, nil)

	_, err := p.Execute(context.Background(), in)

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
}

func TestToolCallArgumentsAreModerated(t *testing.T) {
	t.Parallel()
	stub := &moderationStub{flag: func(s string) bool { return strings.Contains(s, "FLAGGED") }}
	srv := stub.server(t)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
	req := requestContext()
	req.Body = []byte(`{"model":"gpt-4o","messages":[
		{"role":"user","content":"look it up"},
		{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"search","arguments":"{\"q\":\"FLAGGED query\"}"}}]},
		{"role":"tool","tool_call_id":"call_1","content":"ok"}]}`)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), req, nil, nil)

	_, err := p.Execute(context.Background(), in)

	_, ok := appplugins.AsPluginError(err)
	assert.True(t, ok, "got %v", err)
}

func rateLimitOn(t *testing.T, nth int32) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) == nth {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(rateLimited))
			return
		}
		_, _ = w.Write([]byte(`{"id":"modr-1","model":"omni-moderation-latest","results":[{"flagged":false,"categories":{"hate":false},"category_scores":{"hate":0.01}}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// lateMarker ends a text so that the one chunk that carries it is among the last
// dispatched, whatever order the parallel calls reach the stub in.
const lateMarker = " ZZLATEZZ"

func rateLimitOnMarker(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(raw), lateMarker) {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(rateLimited))
			return
		}
		_, _ = w.Write([]byte(`{"id":"modr-1","model":"omni-moderation-latest","results":[{"flagged":false,"categories":{"hate":false},"category_scores":{"hate":0.01}}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A throttle on a chunk of the first round has nothing of the request's own
// before it: it is other traffic, so it fails open as the provider's load.
func TestARateLimitOnAFirstRoundChunkOfALongTextFailsOpen(t *testing.T) {
	t.Parallel()
	srv, _ := rateLimitOn(t, 1)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), chatRequestOf(t, benignText(300)), nil, event)

	res, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	require.NotNil(t, res)
	extras, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok)
	assert.Equal(t, "availability", extras.FailureClass)
	assert.Equal(t, appplugins.DetailThrottled, extras.FailureDetail)
}

func TestARateLimitOnAChunkOfALongTextIsInput(t *testing.T) {
	t.Parallel()
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			srv := rateLimitOnMarker(t)
			p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
			event, span := newEvent()
			in := execInput(policy.StagePreRequest, mode, blockSettings(), chatRequestOf(t, benignText(300)+lateMarker), nil, event)

			res, err := p.Execute(context.Background(), in)

			extras, ok := span.PluginAttrsCopy().Extras.(ModerationData)
			require.True(t, ok)
			assert.Equal(t, "input", extras.FailureClass)
			assert.Equal(t, appplugins.DetailThrottledOversize, extras.FailureDetail)
			if mode == policy.ModeEnforce {
				pe, isPE := appplugins.AsPluginError(err)
				require.True(t, isPE, "got %v", err)
				assert.Equal(t, http.StatusForbidden, pe.StatusCode)
				assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, res)
			assert.Equal(t, appplugins.DecisionFailedOpen, extras.Decision)
		})
	}
}

func TestARateLimitOnASingleRequestFailsOpenAsThrottled(t *testing.T) {
	t.Parallel()
	srv, _ := rateLimitOn(t, 1)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), chatRequestOf(t, "a short question"), nil, event)

	res, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	require.NotNil(t, res)
	extras, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok)
	assert.Equal(t, "availability", extras.FailureClass)
	assert.Equal(t, appplugins.DetailThrottled, extras.FailureDetail)
	assert.Equal(t, appplugins.DecisionFailedOpen, extras.Decision)
}

func TestAFlaggedChunkBlocksEvenWhenAnotherChunkFailed(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"id":"modr-1","model":"omni-moderation-latest","results":[{"flagged":true,"categories":{"hate":true},"category_scores":{"hate":0.97}}]}`))
	}))
	t.Cleanup(srv.Close)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), chatRequestOf(t, benignText(100)), nil, event)

	_, err := p.Execute(context.Background(), in)

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
	extras, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok)
	assert.Equal(t, "block", extras.Decision)
	assert.InDelta(t, 0.97, extras.MaxScore, 0.001)
}

func TestAnObserveRunScreensEveryChunkAndEnforceStopsAtTheFirstFlag(t *testing.T) {
	t.Parallel()
	build := func() (*httptest.Server, *atomic.Int32) {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"modr-1","model":"omni-moderation-latest","results":[{"flagged":true,"categories":{"hate":true},"category_scores":{"hate":0.97}}]}`))
		}))
		t.Cleanup(srv.Close)
		return srv, &calls
	}
	text := benignText(600)
	total := int32(0)
	{
		stub := &moderationStub{}
		srv := stub.server(t)
		p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
		_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeObserve, blockSettings(), chatRequestOf(t, text), nil, nil))
		require.NoError(t, err)
		total = int32(len(stub.requests()))
	}
	require.Greater(t, total, int32(8))

	enforceSrv, enforceCalls := build()
	p := New(adapter.NewRegistry(), enforceSrv.URL, pluginTestTimeout, nil)
	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), chatRequestOf(t, text), nil, nil))
	require.Error(t, err)
	assert.Less(t, enforceCalls.Load(), total)

	observeSrv, observeCalls := build()
	p = New(adapter.NewRegistry(), observeSrv.URL, pluginTestTimeout, nil)
	res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeObserve, blockSettings(), chatRequestOf(t, text), nil, nil))
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, total, observeCalls.Load())
}

func TestAThresholdedCategoryMissingFromOneChunkFailsOpen(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) == 2 {
			_, _ = w.Write([]byte(`{"id":"modr-1","model":"omni-moderation-latest","results":[{"flagged":false,"categories":{},"category_scores":{}}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"modr-1","model":"omni-moderation-latest","results":[{"flagged":false,"categories":{"hate":false},"category_scores":{"hate":0.01}}]}`))
	}))
	t.Cleanup(srv.Close)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), chatRequestOf(t, benignText(100)), nil, event)

	res, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	require.NotNil(t, res)
	extras, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok)
	assert.Equal(t, string(appplugins.FailureVerdictIncomplete), extras.FailureReason)
	assert.Equal(t, "hate", extras.FailureDetail)
}

// pemLike is a secret as long as a PEM key or a service-account JSON, with the
// line breaks such text has: a chunk may end at one of them, inside the secret.
func pemLike(bytes int) string {
	var b strings.Builder
	b.WriteString("SECRET-BEGIN\n")
	for b.Len() < bytes-len("SECRET-END") {
		b.WriteString(strings.Repeat("k", 63) + "\n")
	}
	b.WriteString("SECRET-END")
	return b.String()
}

// The overlap is what lets a secret that a cut falls inside be seen whole in the
// next chunk: here 3,000 of its 3,500 bytes are in the first chunk.
func TestALongSecretThatACutFallsInsideIsSeenWholeInOneChunk(t *testing.T) {
	t.Parallel()
	stub := &moderationStub{flag: func(s string) bool {
		return strings.Contains(s, "SECRET-BEGIN") && strings.Contains(s, "SECRET-END")
	}}
	srv := stub.server(t)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
	text := benignText(32)[:chunkBytes-3000] + " " + pemLike(3500) + " " + benignText(5)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), chatRequestOf(t, text), nil, nil)

	_, err := p.Execute(context.Background(), in)

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
}
