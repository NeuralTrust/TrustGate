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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func streamSettings(over map[string]any) map[string]any {
	stream := map[string]any{"enabled": true}
	for k, v := range over {
		stream[k] = v
	}
	return map[string]any{
		"api_key":    "secret",
		"thresholds": map[string]any{"hate": 0.7},
		"streaming":  stream,
	}
}

func streamPlugin(t *testing.T, f *fakeModerator) *Plugin {
	t.Helper()
	srv := newModeratorServer(t, f)
	return New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
}

func block(seq int, accumulated string) appplugins.StreamSegment {
	return appplugins.StreamSegment{StreamID: "s-1", Seq: seq, Accumulated: accumulated}
}

func TestStreamSettingsOptIn(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "http://example.invalid", pluginTestTimeout, nil)

	cases := []struct {
		name     string
		settings map[string]any
		want     bool
	}{
		{"absent block", map[string]any{"api_key": "k"}, false},
		{"explicitly disabled", map[string]any{"api_key": "k", "streaming": map[string]any{"enabled": false}}, false},
		{"enabled", streamSettings(nil), true},
		{
			"enabled but the response stage is not selected",
			map[string]any{"api_key": "k", "stages": []string{"pre_request"},
				"streaming": map[string]any{"enabled": true}},
			false,
		},
		{
			"enabled but the settings do not parse",
			map[string]any{"streaming": map[string]any{"enabled": true}},
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, _ := p.StreamSettings(tc.settings)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestStreamSettingsCarriesTheKnobs(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "http://example.invalid", pluginTestTimeout, nil)
	on, opts := p.StreamSettings(streamSettings(map[string]any{
		"head_chars":              222,
		"min_chars_between_evals": 333,
		"max_hold_ms":             444,
		"max_accumulated_bytes":   8192,
		"on_error":                "fail_open",
	}))

	require.True(t, on)
	assert.Equal(t, 222, opts.HeadChars)
	assert.Equal(t, 333, opts.MinCharsBetweenEvals)
	assert.Equal(t, 444, opts.MaxHoldMS)
	assert.Equal(t, 8192, opts.MaxAccumulatedBytes)
	assert.Equal(t, "fail_open", opts.OnError)
}

func TestStreamSettingsDefaultsToFailClosed(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "http://example.invalid", pluginTestTimeout, nil)
	on, opts := p.StreamSettings(streamSettings(nil))

	require.True(t, on)
	assert.Equal(t, "fail_closed", opts.OnError,
		"the buffered leg fails closed in enforce; the stream leg must not be laxer by default")
}

func TestInspectSegmentAllowsCleanText(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{response: moderationResponse{Results: []moderationResult{{
		CategoryScores: map[string]float64{"hate": 0.01},
	}}}}
	p := streamPlugin(t, f)

	got, err := p.InspectSegment(context.Background(),
		execInput(policy.StagePreResponse, policy.ModeEnforce, streamSettings(nil), requestContext(), nil, nil),
		block(1, "a harmless paragraph"))

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.False(t, got.Block)
	assert.Equal(t, 1, f.count())
}

func TestInspectSegmentBlocksOnAViolation(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{response: flaggedHateResponse()}
	p := streamPlugin(t, f)

	got, err := p.InspectSegment(context.Background(),
		execInput(policy.StagePreResponse, policy.ModeEnforce, streamSettings(nil), requestContext(), nil, nil),
		block(2, "hateful answer"))

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, got.Block)
	assert.Equal(t, typeContentFlagged, got.Type)
	assert.Equal(t, defaultStreamBlockMessage, got.Message)
	assert.NotContains(t, got.Message, "request",
		"the buffered default says \"request blocked\", which is wrong for a response cut")
}

func TestInspectSegmentUsesTheConfiguredMessage(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{response: flaggedHateResponse()}
	p := streamPlugin(t, f)
	settings := streamSettings(nil)
	settings["action"] = map[string]any{"message": "no."}

	got, err := p.InspectSegment(context.Background(),
		execInput(policy.StagePreResponse, policy.ModeEnforce, settings, requestContext(), nil, nil),
		block(1, "hateful answer"))

	require.NoError(t, err)
	assert.Equal(t, "no.", got.Message)
}

// The whole prefix is what carries the context that made a category a
// violation; a block in isolation loses it.
func TestInspectSegmentModeratesTheAccumulatedPrefix(t *testing.T) {
	t.Parallel()
	var sent moderationRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&sent)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(moderationResponse{Results: []moderationResult{{}}})
	}))
	t.Cleanup(srv.Close)
	p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)

	seg := appplugins.StreamSegment{
		StreamID: "s-1", Seq: 3,
		Text:        "only the last delta",
		Accumulated: "everything produced so far",
	}
	_, err := p.InspectSegment(context.Background(),
		execInput(policy.StagePreResponse, policy.ModeEnforce, streamSettings(nil), requestContext(), nil, nil),
		seg)

	require.NoError(t, err)
	require.Len(t, sent.Input, 1)
	assert.Equal(t, "everything produced so far", sent.Input[0].Text)
}

func TestInspectSegmentSkipsEmptyText(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{response: flaggedHateResponse()}
	p := streamPlugin(t, f)

	got, err := p.InspectSegment(context.Background(),
		execInput(policy.StagePreResponse, policy.ModeEnforce, streamSettings(nil), requestContext(), nil, nil),
		block(1, "   \n  "))

	require.NoError(t, err)
	assert.False(t, got.Block)
	assert.Zero(t, f.count(), "whitespace must not cost a moderation call")
}

// on_error is the guard's to resolve: only it knows whether the status is still
// uncommitted, which is what makes fail_closed a clean 403 at the head and a
// terminator after it.
func TestInspectSegmentReturnsTheCallFailure(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{status: http.StatusInternalServerError, rawBody: `{"error":"nope"}`}
	p := streamPlugin(t, f)

	got, err := p.InspectSegment(context.Background(),
		execInput(policy.StagePreResponse, policy.ModeEnforce, streamSettings(nil), requestContext(), nil, nil),
		block(4, "some text"))

	require.Error(t, err)
	assert.Nil(t, got, "a failure must not be reported as a clean allow")
	assert.Contains(t, err.Error(), "block 4")
}

func TestInspectSegmentHonoursTheGuardTimeout(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	t.Cleanup(srv.Close)
	p := New(adapter.NewRegistry(), srv.URL, 5*time.Second, nil)

	start := time.Now()
	_, err := p.InspectSegment(context.Background(),
		execInput(policy.StagePreResponse, policy.ModeEnforce,
			streamSettings(map[string]any{"guard_timeout": "300ms"}), requestContext(), nil, nil),
		block(1, "some text"))

	require.Error(t, err)
	assert.Less(t, time.Since(start), time.Second,
		"the client is holding bytes; the block deadline must win over the plugin's own")
}

func TestInspectSegmentIsInertWithoutTheOptIn(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{response: flaggedHateResponse()}
	p := streamPlugin(t, f)

	got, err := p.InspectSegment(context.Background(),
		execInput(policy.StagePreResponse, policy.ModeEnforce, blockSettings(), requestContext(), nil, nil),
		block(1, "hateful answer"))

	require.NoError(t, err)
	assert.False(t, got.Block)
	assert.Zero(t, f.count(), "a policy that did not opt in must cost no call")
}

func TestClosingSegmentPublishesTheStreamAccount(t *testing.T) {
	t.Parallel()
	f := &fakeModerator{response: flaggedHateResponse()}
	p := streamPlugin(t, f)
	event, span := newEvent()

	_, err := p.InspectSegment(context.Background(),
		execInput(policy.StagePreResponse, policy.ModeEnforce, streamSettings(nil), requestContext(), nil, event),
		appplugins.StreamSegment{
			StreamID: "s-1", Closing: true,
			Report: appplugins.StreamReport{
				Evals: 5, GuardCalls: 5, CutAtEval: 3, CutOffsetChars: 438,
				GuardLatency: 700 * time.Millisecond, FinalPass: true,
			},
		})
	require.NoError(t, err)
	assert.Zero(t, f.count(), "the closing segment asks for no verdict")

	data, ok := span.PluginAttrsCopy().Extras.(ModerationData)
	require.True(t, ok, "extras must carry the moderation data")
	require.NotNil(t, data.Streaming)
	assert.True(t, data.Streaming.Enabled)
	assert.Equal(t, 5, data.Streaming.EvalsTotal)
	assert.Equal(t, 3, data.Streaming.CutAtEval)
	assert.Equal(t, 438, data.Streaming.CutOffsetChars)
	assert.Equal(t, int64(700), data.Streaming.GuardLatencyMsTotal)
	assert.Equal(t, decisionBlock, data.Decision, "a cut stream is a block, not an allow")
}

func TestClosingSegmentDecisionFollowsTheOutcome(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		report   appplugins.StreamReport
		findings []appplugins.StreamFinding
		want     string
	}{
		{"clean", appplugins.StreamReport{Evals: 4, GuardCalls: 4}, nil, decisionAllowed},
		{
			"reported but not cut",
			appplugins.StreamReport{Evals: 4, GuardCalls: 4},
			[]appplugins.StreamFinding{{Entry: "p", Fingerprint: "abcd"}},
			decisionReported,
		},
		{"cut", appplugins.StreamReport{Evals: 3, GuardCalls: 3, CutAtEval: 2}, nil, decisionBlock},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := New(adapter.NewRegistry(), "http://example.invalid", pluginTestTimeout, nil)
			event, span := newEvent()

			_, err := p.InspectSegment(context.Background(),
				execInput(policy.StagePreResponse, policy.ModeEnforce, streamSettings(nil),
					requestContext(), nil, event),
				appplugins.StreamSegment{
					StreamID: "s-1", Closing: true,
					Report: tc.report, Findings: tc.findings,
				})

			require.NoError(t, err)
			data, ok := span.PluginAttrsCopy().Extras.(ModerationData)
			require.True(t, ok)
			assert.Equal(t, tc.want, data.Decision)
		})
	}
}

func TestViolationFingerprintsAreStableAsThePrefixGrows(t *testing.T) {
	t.Parallel()
	early := violationFingerprints(policy.ModeObserve,
		[]violation{{Category: "hate", Score: 0.71, Threshold: 0.7}})
	later := violationFingerprints(policy.ModeObserve,
		[]violation{{Category: "hate", Score: 0.93, Threshold: 0.7}})

	require.Len(t, early, 1)
	assert.Equal(t, early, later,
		"the score grows with the prefix; keying on it would count blocks, not incidents")
}

func TestViolationFingerprintsSeparateTheRuleThatFired(t *testing.T) {
	t.Parallel()
	threshold := violationFingerprints(policy.ModeObserve,
		[]violation{{Category: "hate", Score: 0.8, Threshold: 0.7}})
	flagged := violationFingerprints(policy.ModeObserve,
		[]violation{{Category: "hate", Score: 0.8}})
	other := violationFingerprints(policy.ModeObserve,
		[]violation{{Category: "violence", Score: 0.8, Threshold: 0.7}})

	assert.NotEqual(t, threshold, flagged, "crossing a threshold and being flagged upstream differ")
	assert.NotEqual(t, threshold, other, "two categories must not fold into one key")
}

func TestViolationFingerprintsDedupeAndSkipBlockingModes(t *testing.T) {
	t.Parallel()
	dupes := []violation{
		{Category: "hate", Score: 0.8, Threshold: 0.7},
		{Category: "hate", Score: 0.9, Threshold: 0.7},
	}
	assert.Len(t, violationFingerprints(policy.ModeObserve, dupes), 1)
	assert.Nil(t, violationFingerprints(policy.ModeEnforce, dupes),
		"a blocking mode stops the stream, so nothing comes back to deduplicate")
}
