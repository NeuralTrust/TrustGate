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

package trustguard

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func wireExtras(t *testing.T, data guardData) map[string]any {
	t.Helper()
	raw, err := json.Marshal(data)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// failed_closed is the key the console and the telemetry contract read to tell a
// refusal for uninspectable input from a block, so it travels on every
// failed_closed event, buffered and streamed.
func TestFailedClosedTravelsOnTheWire(t *testing.T) {
	t.Parallel()

	t.Run("buffered", func(t *testing.T) {
		t.Parallel()
		f := &fakeGuard{status: http.StatusRequestEntityTooLarge}
		p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
		event, span := newEvent()
		_, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, settings(""), requestContext(), nil, event))
		require.Error(t, err)
		extras, ok := span.PluginAttrsCopy().Extras.(guardData)
		require.True(t, ok)
		wire := wireExtras(t, extras)
		assert.Equal(t, true, wire["failed_closed"])
		assert.Nil(t, wire["failed_open"])
	})
	t.Run("streamed", func(t *testing.T) {
		t.Parallel()
		p := newTestPlugin(t, adapter.NewRegistry(), "")
		event, span := newEvent()
		in := execInputWithEvent(policy.StagePreResponse, policy.ModeEnforce, streamingSettings(nil), segmentRequest(), nil, event)
		_, err := p.InspectSegment(segmentTraceContext(), in, appplugins.StreamSegment{Seq: 2, Closing: true, Report: appplugins.StreamReport{
			Evals: 2, CutAtEval: 2, CutOnFailure: true,
			FailureReason: appplugins.FailureInputTooLarge, FailureDetail: appplugins.DetailPayloadTooLarge,
			FailureClass: appplugins.FailureClassInput,
		}})
		require.NoError(t, err)
		extras, ok := span.PluginAttrsCopy().Extras.(guardData)
		require.True(t, ok)
		assert.Equal(t, true, wireExtras(t, extras)["failed_closed"])
	})
	t.Run("a block does not carry it", func(t *testing.T) {
		t.Parallel()
		wire := wireExtras(t, guardData{Decision: decisionBlocked})
		assert.Nil(t, wire["failed_closed"])
	})
}

// A stream that released blocks the guard failed on says whose failure it was,
// on the same key every other external guardrail writes.
func TestFailedOpenStreamRecordsItsFailureClass(t *testing.T) {
	t.Parallel()
	g := &segmentGuard{status: http.StatusInternalServerError}
	p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)
	event, span := newEvent()
	in := execInputWithEvent(policy.StagePreResponse, policy.ModeEnforce, streamingSettings(nil), segmentRequest(), nil, event)
	ctx := segmentTraceContext()

	_, err := p.InspectSegment(ctx, in, appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"})
	require.NoError(t, err)
	_, err = p.InspectSegment(ctx, in, appplugins.StreamSegment{Seq: 2, Closing: true, Report: appplugins.StreamReport{Evals: 1, GuardCalls: 1}})
	require.NoError(t, err)

	extras, ok := span.PluginAttrsCopy().Extras.(guardData)
	require.True(t, ok)
	assert.Equal(t, decisionFailedOpen, extras.Decision)
	assert.Equal(t, "availability", extras.FailureClass)
}

// In observe a mask that cannot be applied still reports the finding it was
// asked to apply: the verdict is not a cut, but it keeps the fingerprints the
// stream guard folds into the entry's findings, as every other guardrail does.
func TestObserveKeepsTheFindingOfAnUnappliableMask(t *testing.T) {
	t.Parallel()
	g := &segmentGuard{response: GuardResponse{
		Status: statusTransform,
		Findings: []GuardFinding{{
			Source:  &GuardFindingSource{Kind: "plugin", Plugin: "pii", DetectorID: "email"},
			Signal:  &GuardFindingSignal{Type: "pii", Confidence: 0.99},
			Outcome: &GuardFindingOutcome{Action: "mask"},
		}},
	}}
	p := newTestPlugin(t, adapter.NewRegistry(), newSegmentServer(t, g).URL)

	verdict, err := p.InspectSegment(segmentTraceContext(), segmentInputIn(t, policy.ModeObserve),
		appplugins.StreamSegment{Seq: 1, Accumulated: "Hello world"})
	require.NoError(t, err)
	require.NotNil(t, verdict)
	assert.False(t, verdict.Block)
	assert.Len(t, verdict.Fingerprints, 1)
	require.NotNil(t, verdict.Incomplete)
}
