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

package googlemodelarmor

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// failure_mode decides what an availability failure costs a Model Armor
// policy: open (the default) lets the request through, closed refuses it in a
// mode that blocks and records it in observe.

func withFailureMode(set map[string]any, mode string) map[string]any {
	set["failure_mode"] = mode
	return set
}

func TestParseConfigFailureMode(t *testing.T) {
	t.Parallel()

	cfg, err := parseConfig(validSettings())
	require.NoError(t, err)
	assert.Equal(t, pluginutil.FailureModeOpen, cfg.FailureMode, "an absent failure_mode fails open")
	assert.False(t, cfg.failClosedFor(""))

	cfg, err = parseConfig(withFailureMode(validSettings(), "closed"))
	require.NoError(t, err)
	assert.True(t, cfg.failClosedFor(""))

	_, err = parseConfig(withFailureMode(validSettings(), "maybe"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failure_mode must be one of open, closed")
}

// A closed policy whose settings do not parse must not fail open because of an
// unrelated key: failure_mode is read leniently from the raw map.
func TestFailClosedOfReadsUnparseableSettingsLeniently(t *testing.T) {
	t.Parallel()

	assert.True(t, failClosedOf(map[string]any{"Failure_Mode": " CLOSED "}, ""))
	assert.False(t, failClosedOf(map[string]any{"failure_mode": "open"}, ""))
	assert.False(t, failClosedOf(map[string]any{}, ""))
	assert.False(t, failClosedOf(map[string]any{"failure_mode": 1}, ""))
}

func TestExecuteAvailabilityFailureFollowsFailureMode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		failureMode string
		mode        policy.Mode
		refused     bool
		decision    string
	}{
		{"open enforce lets it through", "open", policy.ModeEnforce, false, "failed_open"},
		{"closed enforce refuses it", "closed", policy.ModeEnforce, true, "failed_closed"},
		{"closed observe only records it", "closed", policy.ModeObserve, false, "failed_open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := pluginWithClientError(errors.New("model armor is down"))
			event, span := newStreamEvent()

			in := execInput(policy.StagePreRequest, tc.mode,
				withFailureMode(modelArmorSettings(), tc.failureMode), reqCtx(openAIRequest()), nil)
			in.Event = event
			res, err := p.Execute(context.Background(), in)

			if tc.refused {
				pe, ok := appplugins.AsPluginError(err)
				require.True(t, ok, "want a plugin error, got res=%+v err=%v", res, err)
				assert.Equal(t, http.StatusForbidden, pe.StatusCode)
				assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
			} else {
				assertPassThrough(t, res, err)
			}
			data, ok := span.PluginAttrsCopy().Extras.(*Data)
			require.True(t, ok, "extras = %T, want *Data", span.PluginAttrsCopy().Extras)
			assert.Equal(t, tc.decision, data.Decision)
			assert.Equal(t, "availability", data.FailureClass, "closed keeps the real class")
			if tc.failureMode == "closed" {
				assert.Equal(t, "closed", data.FailureMode)
			} else {
				assert.Empty(t, data.FailureMode, "open events are unchanged")
			}
		})
	}
}

// A block_on filter the template never enabled produced no verdict: a closed
// policy refuses the request instead of passing it as if it had been judged.
func TestExecuteFilterAbsentFromTemplateClosedEnforceRefuses(t *testing.T) {
	t.Parallel()
	p := pluginWithStub(newModelArmorStub(t, http.StatusOK, sdpOnlyAllow))
	event, span := newStreamEvent()

	in := execInput(policy.StagePreRequest, policy.ModeEnforce,
		withFailureMode(modelArmorSettings(), "closed"), reqCtx(openAIRequest()), nil)
	in.Event = event
	_, err := p.Execute(context.Background(), in)

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "want a plugin error, got %v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
	data, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, "failed_closed", data.Decision)
	assert.Equal(t, filterRAI, data.Filter)
	assert.Equal(t, reasonFilterNotInTemplate, data.FailureDetail)
}

// Settings that do not parse (here: no project) are a config failure. A policy
// that asked for closed is refused rather than silently let through.
func TestExecuteUnparseableSettingsClosedEnforceRefuses(t *testing.T) {
	t.Parallel()
	p := pluginWithStub(newModelArmorStub(t, http.StatusOK, allowResponse))
	set := withFailureMode(modelArmorSettings(), "closed")
	delete(set, "project")

	in := execInput(policy.StagePreRequest, policy.ModeEnforce, set, reqCtx(openAIRequest()), nil)
	_, err := p.Execute(context.Background(), in)

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "want a plugin error, got %v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
}

func TestInspectSegmentAvailabilityFailureFollowsFailureMode(t *testing.T) {
	t.Parallel()
	p := pluginWithClientError(errors.New("model armor is down"))

	t.Run("open releases the block", func(t *testing.T) {
		t.Parallel()
		got, err := p.InspectSegment(context.Background(),
			streamInput(policy.ModeEnforce, withFailureMode(streamSettings(nil), "open"), nil), segment(4, "some text"))
		require.Error(t, err, "an open policy hands the failure to the guard, which fails open")
		assert.Nil(t, got)
	})

	t.Run("closed enforce cuts the stream", func(t *testing.T) {
		t.Parallel()
		got, err := p.InspectSegment(context.Background(),
			streamInput(policy.ModeEnforce, withFailureMode(streamSettings(nil), "closed"), nil), segment(4, "some text"))
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.True(t, got.Block)
		assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, got.Type)
		assert.NotNil(t, got.Failure, "the cut must carry the failure for the record")
	})

	t.Run("closed observe only records it", func(t *testing.T) {
		t.Parallel()
		got, err := p.InspectSegment(context.Background(),
			streamInput(policy.ModeObserve, withFailureMode(streamSettings(nil), "closed"), nil), segment(4, "some text"))
		require.Error(t, err, "observe never cuts")
		assert.Nil(t, got)
	})
}

// An invocation that failed outright is availability on the stream: an open
// policy releases the block, and a closed one cuts on it.
func TestInspectSegmentInvocationFailureClosedEnforceCuts(t *testing.T) {
	t.Parallel()
	p := pluginWithStub(newModelArmorStub(t, http.StatusOK, invocationFailureResponse))

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, withFailureMode(streamSettings(nil), "closed"), nil), segment(5, "some text"))

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, got.Block)
}

// A usable mask beside a filter the template never enabled is kept when the
// policy fails open; a closed policy refuses instead, since the filter it asked
// for did not judge the content.
func TestInspectSegmentMaskDespiteGapIsRefusedWhenClosed(t *testing.T) {
	t.Parallel()
	body := sanitizeOpen +
		`"sdp":{"sdpFilterResult":{"deidentifyResult":{"matchState":"MATCH_FOUND","infoTypes":["EMAIL_ADDRESS"],"data":{"text":"write to [EMAIL] soon"}}}}` +
		sanitizeClose
	p := pluginWithStub(newModelArmorStub(t, http.StatusOK, body))

	got, err := p.InspectSegment(context.Background(),
		streamInput(policy.ModeEnforce, withFailureMode(anonymizeStreamSettings(), "closed"), nil),
		segment(2, "write to a@b.com soon"))

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, got.Block)
	assert.False(t, got.HasTransform, "a closed policy must not release the masked text as if it had been judged")
}

// A closed policy whose settings do not parse stays on the stream chain, so
// the failure is refused (or recorded) instead of the response streaming out
// uninspected. An open one still sits the stream out.
func TestStreamSettingsKeepAClosedUnparseablePolicyOnTheStream(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "", 0, true, nil)

	on, opts := p.StreamSettings(map[string]any{"failure_mode": "closed"})
	assert.True(t, on)
	assert.Positive(t, opts.MaxAccumulatedBytes)
	assert.Equal(t, pluginutil.StreamOnErrorFailClosed, opts.OnError)

	on, _ = p.StreamSettings(map[string]any{"failure_mode": "open"})
	assert.False(t, on)
}

// A streamed refusal carries the policy's message, as the buffered leg's does.
func TestInspectSegmentClosedRefusalCarriesThePolicyMessage(t *testing.T) {
	t.Parallel()
	p := pluginWithClientError(errors.New("model armor is down"))
	set := withFailureMode(streamSettings(nil), "closed")
	set["message"] = "Blocked by policy"

	got, err := p.InspectSegment(context.Background(), streamInput(policy.ModeEnforce, set, nil), segment(4, "some text"))

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, got.Block)
	assert.Equal(t, "Blocked by policy", got.Message)
}

// A closed policy whose settings do not parse still writes the stream's record
// on the closing segment, with failure_mode on it.
func TestClosingSegmentOfAClosedUnparseablePolicyIsRecorded(t *testing.T) {
	t.Parallel()
	p := pluginWithStub(newModelArmorStub(t, http.StatusOK, allowResponse))
	event, span := newStreamEvent()
	set := withFailureMode(streamSettings(nil), "closed")
	delete(set, "project")

	got, err := p.InspectSegment(context.Background(), streamInput(policy.ModeEnforce, set, event),
		appplugins.StreamSegment{StreamID: "s-1", Closing: true, Report: appplugins.StreamReport{
			Evals: 1, CutAtEval: 1, CutOnFailure: true,
			FailureReason: appplugins.FailureConfigInvalid, FailureClass: appplugins.FailureClassAvailability,
		}})

	require.NoError(t, err)
	assert.False(t, got.Block)
	data, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok, "extras = %T, want *Data", span.PluginAttrsCopy().Extras)
	assert.Equal(t, string(appplugins.FailureConfigInvalid), data.FailureReason)
	assert.Equal(t, "availability", data.FailureClass)
	assert.Equal(t, "closed", data.FailureMode)
}

// A closed policy reports on_error fail_closed, so the executor cuts a block it
// screens in chunks when a chunk never reached Model Armor. An open one keeps
// fail_open.
func TestStreamSettingsOnErrorFollowsFailureMode(t *testing.T) {
	t.Parallel()
	p := New(adapter.NewRegistry(), "", 0, true, nil)

	on, opts := p.StreamSettings(withFailureMode(streamSettings(nil), "closed"))
	require.True(t, on)
	assert.Equal(t, pluginutil.StreamOnErrorFailClosed, opts.OnError)

	on, opts = p.StreamSettings(withFailureMode(streamSettings(nil), "open"))
	require.True(t, on)
	assert.Equal(t, pluginutil.StreamOnErrorFailOpen, opts.OnError)
}

func TestExecuteMissingTemplateFollowsFailureMode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name        string
		failureMode string
		mode        policy.Mode
		refused     bool
		decision    string
	}{
		{"open enforce lets it through", "open", policy.ModeEnforce, false, "failed_open"},
		{"open observe lets it through", "open", policy.ModeObserve, false, "failed_open"},
		{"closed enforce refuses it", "closed", policy.ModeEnforce, true, "failed_closed"},
		{"closed observe only records it", "closed", policy.ModeObserve, false, "failed_open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := pluginWithStub(newModelArmorStub(t, http.StatusBadRequest, rpcTemplateNotFound))
			event, span := newStreamEvent()

			in := execInput(policy.StagePreRequest, tc.mode,
				withFailureMode(modelArmorSettings(), tc.failureMode), reqCtx(openAIRequest()), nil)
			in.Event = event
			res, err := p.Execute(context.Background(), in)

			if tc.refused {
				pe, ok := appplugins.AsPluginError(err)
				require.True(t, ok, "want a plugin error, got res=%+v err=%v", res, err)
				assert.Equal(t, http.StatusForbidden, pe.StatusCode)
			} else {
				assertPassThrough(t, res, err)
			}
			data, ok := span.PluginAttrsCopy().Extras.(*Data)
			require.True(t, ok)
			assert.Equal(t, tc.decision, data.Decision)
			assert.Equal(t, "availability", data.FailureClass)
			assert.Equal(t, "config_invalid", data.FailureReason)
		})
	}
}
