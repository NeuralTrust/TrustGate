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
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// ENG-1718: failure_mode lets a Model Armor policy refuse what Model Armor
// cannot evaluate, the same contract trustguard's failure_mode has. Open (the
// default) keeps the behaviour every policy had before the setting existed.

func withFailureMode(set map[string]any, mode string) map[string]any {
	set["failure_mode"] = mode
	return set
}

func TestParseConfigFailureMode(t *testing.T) {
	t.Parallel()

	cfg, err := parseConfig(validSettings())
	require.NoError(t, err)
	assert.Equal(t, failureModeOpen, cfg.FailureMode, "an absent failure_mode keeps today's fail-open behaviour")
	assert.False(t, cfg.failClosed())

	cfg, err = parseConfig(withFailureMode(validSettings(), "closed"))
	require.NoError(t, err)
	assert.True(t, cfg.failClosed())

	_, err = parseConfig(withFailureMode(validSettings(), "maybe"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failure_mode must be one of open, closed")
}

// A closed policy whose settings do not parse must not fail open because of an
// unrelated key: failure_mode is read leniently from the raw map.
func TestFailClosedOfReadsUnparseableSettingsLeniently(t *testing.T) {
	t.Parallel()

	assert.True(t, failClosedOf(map[string]any{"Failure_Mode": " CLOSED "}))
	assert.False(t, failClosedOf(map[string]any{"failure_mode": "open"}))
	assert.False(t, failClosedOf(map[string]any{}))
	assert.False(t, failClosedOf(map[string]any{"failure_mode": 1}))
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

// On the stream an invocation that failed outright used to be returned as a
// bare error; a closed policy cuts on it like any other availability failure.
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

	on, _ = p.StreamSettings(map[string]any{"failure_mode": "open"})
	assert.False(t, on)
}
