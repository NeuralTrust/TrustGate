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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const pluginTestTimeout = 2 * time.Second

type fakeModerator struct {
	mu       sync.Mutex
	hits     int
	status   int
	response moderationResponse
	rawBody  string
}

func (f *fakeModerator) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits++
		status := f.status
		if status == 0 {
			status = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if f.rawBody != "" {
			_, _ = io.WriteString(w, f.rawBody)
			return
		}
		_ = json.NewEncoder(w).Encode(f.response)
	}
}

func (f *fakeModerator) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits
}

func newModeratorServer(t *testing.T, f *fakeModerator) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	return srv
}

func flaggedHateResponse() moderationResponse {
	return moderationResponse{
		ID:    "mod-1",
		Model: defaultModel,
		Results: []moderationResult{{
			Flagged:        true,
			Categories:     map[string]bool{"hate": true},
			CategoryScores: map[string]float64{"hate": 0.91},
		}},
	}
}

func blockSettings() map[string]any {
	return map[string]any{
		"api_key":    "secret",
		"thresholds": map[string]any{"hate": 0.7},
	}
}

func requestContext() *infracontext.RequestContext {
	return &infracontext.RequestContext{
		Provider:     "openai",
		SourceFormat: "openai",
		Body:         []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"i hate you"}]}`),
	}
}

func responseContext() *infracontext.ResponseContext {
	return &infracontext.ResponseContext{
		StatusCode: http.StatusOK,
		Body:       []byte(`{"id":"c","object":"chat.completion","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"hateful answer"},"finish_reason":"stop"}]}`),
	}
}

func execInput(stage policy.Stage, mode policy.Mode, set map[string]any, req *infracontext.RequestContext, resp *infracontext.ResponseContext, event *metrics.EventContext) appplugins.ExecInput {
	return appplugins.ExecInput{
		Stage:    stage,
		Mode:     mode,
		Config:   policy.PluginConfig{Settings: set},
		Request:  req,
		Response: resp,
		Event:    event,
	}
}

func newEvent() (*metrics.EventContext, *trace.Span) {
	tr := trace.New("", trace.Metadata{})
	span := tr.StartSpan(trace.SpanPlugin, PluginName)
	return metrics.NewEventContext(span), span
}

func TestPluginContract(t *testing.T) {
	t.Parallel()
	var p appplugins.Plugin = New(adapter.NewRegistry(), "http://example.invalid", pluginTestTimeout, nil)

	assert.Equal(t, PluginName, p.Name())
	assert.Empty(t, p.MandatoryStages())
	assert.ElementsMatch(t, []policy.Stage{policy.StagePreRequest, policy.StagePreResponse}, p.SupportedStages())
	assert.ElementsMatch(t, []policy.Mode{policy.ModeEnforce, policy.ModeObserve}, p.SupportedModes())
	assert.False(t, p.MutatesRequestBody())
	assert.False(t, p.MutatesResponseBody())
	assert.False(t, p.MutatesMetadata())
}

func TestValidateConfig(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "http://example.invalid", pluginTestTimeout, nil)
	require.NoError(t, p.ValidateConfig(map[string]any{"api_key": "k"}))
	require.Error(t, p.ValidateConfig(map[string]any{}))
}

func TestExecuteEnforceBlockReturns403(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{response: flaggedHateResponse()}
	srv := newModeratorServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)

	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), requestContext(), nil, event)
	res, err := p.Execute(context.Background(), in)

	require.Nil(t, res)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "expected *PluginError, got %v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
	assert.Equal(t, typeContentFlagged, pe.Type)

	const wantBody = `{"error":{"type":"content_flagged","categories":[{"category":"hate","score":0.91,"threshold":0.7}]}}`
	assert.JSONEq(t, wantBody, string(pe.Body))
	assert.Equal(t, wantBody, string(pe.Body))

	var decoded struct {
		Error struct {
			Type       string      `json:"type"`
			Categories []violation `json:"categories"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(pe.Body, &decoded))
	assert.Equal(t, typeContentFlagged, decoded.Error.Type)
	require.Len(t, decoded.Error.Categories, 1)
	assert.Equal(t, "hate", decoded.Error.Categories[0].Category)

	data, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok, "expected ModerationData extras")
	assert.Equal(t, decisionBlock, data.Decision)
}

func TestExecuteObserveWithViolationPassesThrough(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{response: flaggedHateResponse()}
	srv := newModeratorServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)

	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeObserve, blockSettings(), requestContext(), nil, event)
	res, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.False(t, res.StopUpstream)

	data, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok, "expected ModerationData extras")
	assert.Equal(t, decisionReported, data.Decision)
	assert.True(t, span.HasDecision())
}

func TestExecuteAllowPassesThrough(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{response: moderationResponse{
		Results: []moderationResult{{
			Categories:     map[string]bool{"hate": false},
			CategoryScores: map[string]float64{"hate": 0.10},
		}},
	}}
	srv := newModeratorServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)

	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), requestContext(), nil, event)
	res, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	data, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok)
	assert.Equal(t, decisionAllowed, data.Decision)
	assert.InDelta(t, 0.10, data.MaxScore, 1e-9)
	assert.Equal(t, "hate", data.MaxScoreCategory)
}

func TestExecutePreResponseBlock(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{response: flaggedHateResponse()}
	srv := newModeratorServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)

	event, _ := newEvent()
	in := execInput(policy.StagePreResponse, policy.ModeEnforce, blockSettings(), requestContext(), responseContext(), event)
	res, err := p.Execute(context.Background(), in)

	require.Nil(t, res)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "expected *PluginError, got %v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
	assert.Equal(t, 1, f.count())
}

func TestExecuteEnforceFailureReturns502(t *testing.T) {
	t.Parallel()
	const secret = "SECRET_OPENAI_DETAIL"
	f := &fakeModerator{status: http.StatusInternalServerError, rawBody: `{"error":"` + secret + `"}`}
	srv := newModeratorServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)

	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), requestContext(), nil, event)
	res, err := p.Execute(context.Background(), in)

	require.Nil(t, res)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "expected *PluginError, got %v", err)
	assert.Equal(t, http.StatusBadGateway, pe.StatusCode)
	assert.Equal(t, typeUnavailable, pe.Type)
	assert.NotContains(t, string(pe.Body), secret)
	assert.NotContains(t, pe.Message, secret)
	assert.Equal(t, unavailableBodyJSON, string(pe.Body))

	data, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok)
	assert.Equal(t, decisionUnavailable, data.Decision)
}

func TestExecuteObserveFailurePassesThrough(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{status: http.StatusInternalServerError, rawBody: `{"error":"boom"}`}
	srv := newModeratorServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)

	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeObserve, blockSettings(), requestContext(), nil, event)
	res, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	data, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok)
	assert.Equal(t, decisionFailedOpen, data.Decision)
}

func TestExecuteStreamingResponseSkipped(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{response: flaggedHateResponse()}
	srv := newModeratorServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)

	resp := responseContext()
	resp.Streaming = true
	in := execInput(policy.StagePreResponse, policy.ModeEnforce, blockSettings(), requestContext(), resp, nil)
	res, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, 0, f.count(), "streaming response must not call the moderations API")
}

func TestExecuteStageNotSelectedPassThrough(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{response: flaggedHateResponse()}
	srv := newModeratorServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)

	set := blockSettings()
	set["stages"] = []string{stagePreResponse}
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, set, requestContext(), nil, nil)
	res, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, 0, f.count())
}

func TestExecuteEmptyAndNilRequestPassThrough(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{response: flaggedHateResponse()}
	srv := newModeratorServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)

	t.Run("empty body", func(t *testing.T) {
		req := requestContext()
		req.Body = nil
		in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), req, nil, nil)
		res, err := p.Execute(context.Background(), in)
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.Equal(t, http.StatusOK, res.StatusCode)
	})

	t.Run("nil request", func(t *testing.T) {
		in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), nil, nil, nil)
		res, err := p.Execute(context.Background(), in)
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.Equal(t, http.StatusOK, res.StatusCode)
	})

	assert.Equal(t, 0, f.count())
}

func TestExecuteEmptyBaseURLPassThrough(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "", pluginTestTimeout, nil)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), requestContext(), nil, nil)
	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestExecuteInvalidConfigErrors(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "http://example.invalid", pluginTestTimeout, nil)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, map[string]any{}, requestContext(), nil, nil)
	_, err := p.Execute(context.Background(), in)
	require.Error(t, err)
	_, ok := appplugins.AsPluginError(err)
	assert.False(t, ok, "config error must not be a PluginError")
}
