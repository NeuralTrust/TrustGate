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
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
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

// noThresholdSettings mirrors what the console sends: only api_key, model and
// stages. With no thresholds configured, applyDefaults must turn
// BlockOnFlagged on, or a flagged category can never produce a violation.
func noThresholdSettings() map[string]any {
	return map[string]any{
		"api_key": "secret",
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
	assert.ElementsMatch(t, []policy.Stage{policy.StagePreRequest}, p.MandatoryStages())
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

	wantBody := `{"error":{"type":"content_flagged","message":"` + appplugins.DefaultBlockMessage + `","categories":[{"category":"hate","score":0.91,"threshold":0.7}]}}`
	assert.JSONEq(t, wantBody, string(pe.Body))
	assert.Equal(t, wantBody, string(pe.Body))

	var decoded struct {
		Error struct {
			Type       string      `json:"type"`
			Message    string      `json:"message"`
			Categories []violation `json:"categories"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(pe.Body, &decoded))
	assert.Equal(t, typeContentFlagged, decoded.Error.Type)
	assert.Equal(t, appplugins.DefaultBlockMessage, decoded.Error.Message)
	require.Len(t, decoded.Error.Categories, 1)
	assert.Equal(t, "hate", decoded.Error.Categories[0].Category)

	data, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok, "expected ModerationData extras")
	assert.Equal(t, decisionBlock, data.Decision)
}

func TestExecuteEnforceBlockSurfacesCustomMessage(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{response: flaggedHateResponse()}
	srv := newModeratorServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)

	settings := blockSettings()
	settings["action"] = map[string]any{"message": "blocked by policy XYZ"}
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings, requestContext(), nil, nil)
	_, err := p.Execute(context.Background(), in)

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "expected *PluginError, got %v", err)
	var decoded struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(pe.Body, &decoded))
	assert.Equal(t, "blocked by policy XYZ", decoded.Error.Message)
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
	assert.Equal(t, "reported", span.PluginAttrsCopy().Decision)
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
	assert.Equal(t, "allowed", span.PluginAttrsCopy().Decision)
	assert.InDelta(t, 0.10, data.MaxScore, 1e-9)
	assert.Equal(t, "hate", data.MaxScoreCategory)
}

func TestExecuteEnforceNoThresholdsFlaggedBlocks(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{response: flaggedHateResponse()}
	srv := newModeratorServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)

	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, noThresholdSettings(), requestContext(), nil, event)
	res, err := p.Execute(context.Background(), in)

	require.Nil(t, res)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "expected *PluginError, got %v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
	assert.Equal(t, typeContentFlagged, pe.Type)

	data, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok, "expected ModerationData extras")
	assert.Equal(t, decisionBlock, data.Decision)
}

func TestExecuteObserveNoThresholdsFlaggedReports(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{response: flaggedHateResponse()}
	srv := newModeratorServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)

	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeObserve, noThresholdSettings(), requestContext(), nil, event)
	res, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.False(t, res.StopUpstream)

	data, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok, "expected ModerationData extras")
	assert.Equal(t, decisionReported, data.Decision)
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

func TestExecuteEnforceFailurePassesThrough(t *testing.T) {
	t.Parallel()
	const secret = "SECRET_OPENAI_DETAIL"
	f := &fakeModerator{status: http.StatusInternalServerError, rawBody: `{"error":"` + secret + `"}`}
	srv := newModeratorServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)

	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), requestContext(), nil, event)
	res, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Nil(t, res.Body, "the upstream error text must never reach the client")

	data, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok)
	assert.Equal(t, "failed_open", data.Decision)
	assert.Equal(t, "transport", data.FailureReason)
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
	assert.Equal(t, "failed_open", data.Decision)
	assert.Equal(t, "transport", data.FailureReason)
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

func TestExecuteInvalidConfigEnforceFailsOpen(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "http://example.invalid", pluginTestTimeout, nil)
	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, map[string]any{}, requestContext(), nil, event)
	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	data, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok)
	assert.Equal(t, "failed_open", data.Decision)
	assert.Equal(t, "config_invalid", data.FailureReason)
}

func TestExecuteInvalidConfigObserveFailsOpen(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "http://example.invalid", pluginTestTimeout, nil)
	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeObserve, map[string]any{}, requestContext(), nil, event)
	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	data, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok)
	assert.Equal(t, "failed_open", data.Decision)
	assert.Equal(t, "config_invalid", data.FailureReason)
}

// missingThresholdSettings asks for a threshold on "violence", a category
// known for the default model, but the fake server's response (below) never
// mentions it - the gap missingKnownThreshold exists to catch: evaluationSet
// only draws from Categories (unset here) or the response's own keys, so
// without this rule "violence" is silently dropped rather than evaluated.
func missingThresholdSettings() map[string]any {
	return map[string]any{
		"api_key":    "secret",
		"thresholds": map[string]any{CategoryViolence: 0.5},
	}
}

func TestExecuteVerdictIncompleteEnforceFailsOpen(t *testing.T) {
	t.Parallel()
	// Below its own configured threshold ("hate" is not even asked for
	// here), so nothing about this response looks like a block - the only
	// reason to refuse it is the missing "violence" category.
	f := &fakeModerator{response: moderationResponse{
		Results: []moderationResult{{
			Categories:     map[string]bool{"hate": false},
			CategoryScores: map[string]float64{"hate": 0.10},
		}},
	}}
	srv := newModeratorServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)

	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, missingThresholdSettings(), requestContext(), nil, event)
	res, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	data, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok)
	assert.Equal(t, "failed_open", data.Decision)
	assert.Equal(t, "verdict_incomplete", data.FailureReason)
	assert.Equal(t, CategoryViolence, data.FailureDetail)
}

func TestExecuteVerdictIncompleteObserveFailsOpen(t *testing.T) {
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
	in := execInput(policy.StagePreRequest, policy.ModeObserve, missingThresholdSettings(), requestContext(), nil, event)
	res, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	data, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok)
	assert.Equal(t, "failed_open", data.Decision)
	assert.Equal(t, "verdict_incomplete", data.FailureReason)
	assert.Equal(t, CategoryViolence, data.FailureDetail)
}

// TestExecuteUnknownThresholdKeyMissingFromResponseDoesNotTriggerVerdictIncomplete
// proves the rule ignores a threshold key this build does not recognise: a
// legacy typo'd category must keep behaving exactly as it did before this
// rule existed (silently never firing), not suddenly start failing closed.
func TestExecuteUnknownThresholdKeyMissingFromResponseDoesNotTriggerVerdictIncomplete(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{response: moderationResponse{
		Results: []moderationResult{{
			Categories:     map[string]bool{"hate": false},
			CategoryScores: map[string]float64{"hate": 0.10},
		}},
	}}
	srv := newModeratorServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)

	settings := map[string]any{
		"api_key":    "secret",
		"thresholds": map[string]any{"hate/threatning": 0.5},
	}
	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings, requestContext(), nil, event)
	res, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	data, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok)
	assert.Equal(t, decisionAllowed, data.Decision)
	assert.Empty(t, data.FailureReason)
}

// TestWarnUnknownConfigLogsOnceThenAgainOnANewGap proves the load-time
// warning is deduped per distinct (config id, model, unknown keys)
// fingerprint: the same bad config logs once across repeated requests, but a
// different gap on the same config (an edit that introduces a new typo)
// warns again rather than going silent forever after the first hit.
func TestWarnUnknownConfigLogsOnceThenAgainOnANewGap(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	// Below its threshold, so nothing here blocks - only the warning is
	// under test.
	f := &fakeModerator{response: moderationResponse{
		Results: []moderationResult{{
			Categories:     map[string]bool{"hate": false},
			CategoryScores: map[string]float64{"hate": 0.10},
		}},
	}}
	srv := newModeratorServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, logger)

	settings := map[string]any{
		"api_key":    "secret",
		"thresholds": map[string]any{"hate": 0.99, "hate/threatning": 0.5},
	}
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings, requestContext(), nil, nil)

	for i := 0; i < 3; i++ {
		res, err := p.Execute(context.Background(), in)
		require.NoError(t, err)
		require.NotNil(t, res)
	}
	const warnMsg = "openai moderation config names an unrecognised model or category"
	assert.Equal(t, 1, strings.Count(buf.String(), warnMsg),
		"expected exactly one warning across three identical requests, got log:\n%s", buf.String())
	assert.NotContains(t, buf.String(), "secret", "the api_key must never be logged")

	// A different gap on the same config id (Config.ID is empty in both,
	// matching a real update that keeps the same policy plugin row) warns
	// again instead of being permanently suppressed by the first hit.
	settings2 := map[string]any{
		"api_key":    "secret",
		"thresholds": map[string]any{"hate": 0.99, "another-typo": 0.5},
	}
	in2 := execInput(policy.StagePreRequest, policy.ModeEnforce, settings2, requestContext(), nil, nil)
	res, err := p.Execute(context.Background(), in2)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 2, strings.Count(buf.String(), warnMsg))
}

// explicitNoBlockSettings is what an operator gets by explicitly disabling
// BlockOnFlagged without configuring any thresholds: parseConfig honours it as
// sent (see config.go), so evaluate() can never raise a violation. This is the
// combination ValidateSettingsWrite must refuse on write.
func explicitNoBlockSettings() map[string]any {
	return map[string]any{
		"api_key":          "secret",
		"block_on_flagged": false,
	}
}

func TestValidateSettingsWrite(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "http://example.invalid", pluginTestTimeout, nil)

	tests := []struct {
		name     string
		settings map[string]any
		previous map[string]any
		wantErr  bool
	}{
		{
			name:     "block_on_flagged absent defaults true, no thresholds needed",
			settings: noThresholdSettings(),
			wantErr:  false,
		},
		{
			name:     "block_on_flagged explicit true",
			settings: map[string]any{"api_key": "secret", "block_on_flagged": true},
			wantErr:  false,
		},
		{
			name:     "block_on_flagged false with thresholds configured",
			settings: map[string]any{"api_key": "secret", "block_on_flagged": false, "thresholds": map[string]any{"hate": 0.7}},
			wantErr:  false,
		},
		{
			name:     "block_on_flagged explicit false with no thresholds is rejected",
			settings: explicitNoBlockSettings(),
			wantErr:  true,
		},
		{
			name:     "invalid settings surface the parseConfig error",
			settings: map[string]any{},
			wantErr:  true,
		},
		{
			name:     "unknown threshold key on create is rejected",
			settings: map[string]any{"api_key": "secret", "thresholds": map[string]any{"hate/threatning": 0.7}},
			wantErr:  true,
		},
		{
			name:     "unknown categories entry on create is rejected",
			settings: map[string]any{"api_key": "secret", "categories": []any{"hate", "hate/threatning"}},
			wantErr:  true,
		},
		{
			name:     "unknown model on create is rejected",
			settings: map[string]any{"api_key": "secret", "model": "gpt-4o-moderation"},
			wantErr:  true,
		},
		{
			name: "known model, known keys pass",
			settings: map[string]any{
				"api_key":    "secret",
				"model":      ModelOmniLatest,
				"thresholds": map[string]any{CategoryHate: 0.7, CategoryViolence: 0.5},
				"categories": []any{CategoryHate, CategoryViolence},
			},
			wantErr: false,
		},
		{
			name:     "retired text-moderation model is rejected on create",
			settings: map[string]any{"api_key": "secret", "model": "text-moderation-latest"},
			wantErr:  true,
		},
		{
			name:     "a stored retired text-moderation model stays editable",
			settings: map[string]any{"api_key": "rotated", "model": "text-moderation-stable"},
			previous: map[string]any{"api_key": "secret", "model": "text-moderation-stable"},
			wantErr:  false,
		},
		{
			name: "update where the bad key already existed in previous passes",
			settings: map[string]any{
				"api_key":    "secret",
				"thresholds": map[string]any{"hate/threatning": 0.7},
			},
			previous: map[string]any{
				"api_key":    "secret",
				"thresholds": map[string]any{"hate/threatning": 0.6},
			},
			wantErr: false,
		},
		{
			name: "update adding a new bad key alongside an old bad key passes only the old one",
			settings: map[string]any{
				"api_key":    "secret",
				"thresholds": map[string]any{"hate/threatning": 0.7, "brand-new-typo": 0.4},
			},
			previous: map[string]any{
				"api_key":    "secret",
				"thresholds": map[string]any{"hate/threatning": 0.6},
			},
			wantErr: true,
		},
		{
			name: "switching a policy to a retired model is rejected",
			settings: map[string]any{
				"api_key":    "secret",
				"model":      "text-moderation-latest",
				"thresholds": map[string]any{CategoryHate: 0.5},
			},
			previous: map[string]any{
				"api_key":    "secret",
				"model":      ModelOmniLatest,
				"thresholds": map[string]any{CategoryHate: 0.5},
			},
			wantErr: true,
		},
		{
			name: "model change keeps a key already present pre-existing across the change",
			settings: map[string]any{
				"api_key":    "secret",
				"model":      ModelOmni20240926,
				"thresholds": map[string]any{"hate/threatning": 0.5},
			},
			previous: map[string]any{
				"api_key":    "secret",
				"model":      ModelOmniLatest,
				"thresholds": map[string]any{"hate/threatning": 0.5},
			},
			wantErr: false,
		},
		{
			name:     "unknown model matching the previously stored model stays editable",
			settings: map[string]any{"api_key": "secret", "model": "gpt-4o-moderation"},
			previous: map[string]any{"api_key": "secret", "model": "gpt-4o-moderation"},
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := p.ValidateSettingsWrite(tt.settings, tt.previous)
			if !tt.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
		})
	}
}

func TestValidateSettingsWrite_RejectionExplainsTheFix(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "http://example.invalid", pluginTestTimeout, nil)
	err := p.ValidateSettingsWrite(explicitNoBlockSettings(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "thresholds")
	assert.Contains(t, err.Error(), "block_on_flagged")
}

// TestValidateSettingsWrite_UnknownKeyMessageNamesTheKey proves the write
// rejection is actionable: an operator reading it sees exactly which key was
// wrong and which model it was checked against, not a generic failure.
func TestValidateSettingsWrite_UnknownKeyMessageNamesTheKey(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "http://example.invalid", pluginTestTimeout, nil)
	err := p.ValidateSettingsWrite(map[string]any{
		"api_key":    "secret",
		"thresholds": map[string]any{"hate/threatning": 0.7},
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hate/threatning")
	assert.Contains(t, err.Error(), ModelOmniLatest)
	assert.Contains(t, err.Error(), "openai_moderation:")
}

// TestValidateSettingsWrite_UnknownModelMessageListsValidModels covers the
// model-level rejection's own message shape.
func TestValidateSettingsWrite_UnknownModelMessageListsValidModels(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "http://example.invalid", pluginTestTimeout, nil)
	err := p.ValidateSettingsWrite(map[string]any{"api_key": "secret", "model": "gpt-4o-moderation"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gpt-4o-moderation")
	assert.Contains(t, err.Error(), ModelOmniLatest)
	assert.Contains(t, err.Error(), "openai_moderation:")
}

// TestValidateSettingsWrite_NewBadKeyErrorNamesOnlyTheNewOne is the sharper
// form of the "adding a new bad key alongside an old one" case: the error
// must mention the newly introduced typo and must not mention the
// grandfathered one, or an operator fixing the reported key would still be
// left with a rejected write.
func TestValidateSettingsWrite_NewBadKeyErrorNamesOnlyTheNewOne(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "http://example.invalid", pluginTestTimeout, nil)
	err := p.ValidateSettingsWrite(map[string]any{
		"api_key":    "secret",
		"thresholds": map[string]any{"hate/threatning": 0.7, "brand-new-typo": 0.4},
	}, map[string]any{
		"api_key":    "secret",
		"thresholds": map[string]any{"hate/threatning": 0.6},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "brand-new-typo")
	assert.NotContains(t, err.Error(), "hate/threatning")
}

// TestExecuteExplicitNoBlockNoThresholdsStillExecutes proves the write-time
// rejection in ValidateSettingsWrite does not change parseConfig/Execute
// semantics: a stored policy with this combination (created before the guard
// existed, or loaded from a snapshot) must keep running exactly as before -
// no error, verdict decided by the flagged categories alone (none configured,
// so it never blocks or reports, matching the explicit request).
func TestExecuteExplicitNoBlockNoThresholdsStillExecutes(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{response: flaggedHateResponse()}
	srv := newModeratorServer(t, f)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)

	event, span := newEvent()
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, explicitNoBlockSettings(), requestContext(), nil, event)
	res, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)

	data, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok, "expected ModerationData extras")
	assert.Equal(t, decisionAllowed, data.Decision)
}

func TestValidateSettingsWriteRejectsFinalPassOptOut(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "http://example.invalid", pluginTestTimeout, nil)
	settings := noThresholdSettings()
	settings["streaming"] = map[string]any{"final_pass": false}

	err := p.ValidateSettingsWrite(settings, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "streaming.final_pass")
	require.NoError(t, p.ValidateSettingsWrite(settings, settings),
		"a policy already stored with final_pass: false must stay editable")
	require.NoError(t, p.ValidateConfig(settings), "the rule applies on write only, never when a policy loads")
}

func TestExecuteFailureFailsClosedWhenThePolicyAsks(t *testing.T) {
	t.Parallel()
	srv := newModeratorServer(t, &fakeModerator{status: http.StatusInternalServerError, rawBody: `{"error":"boom"}`})
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
	settings := blockSettings()
	settings["on_error"] = "fail_closed"

	event, _ := newEvent()
	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings, requestContext(), nil, event))

	var pluginErr *appplugins.PluginError
	require.ErrorAs(t, err, &pluginErr)
	assert.Equal(t, http.StatusBadGateway, pluginErr.StatusCode)
}

func TestParseConfigRejectsAnUnknownOnError(t *testing.T) {
	t.Parallel()
	settings := blockSettings()
	settings["on_error"] = "retry"

	_, err := parseConfig(settings)
	require.Error(t, err)
}
