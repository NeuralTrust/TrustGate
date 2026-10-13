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

package proxy

import (
	"context"
	"strings"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runNativeGuardTraced is runNativeGuard with a request trace on the context, so
// a test can read the policy-chain entries the guard recorded.
func runNativeGuardTraced(t *testing.T, g *streamGuard, frames [][]byte) ([][]byte, *appplugins.PluginError, *trace.RequestTrace) {
	t.Helper()
	rt := trace.New("native-stream-trace", trace.Metadata{})
	out, pe := g.Run(trace.NewContext(context.Background(), rt), frameSeq(frames))
	if pe != nil {
		return nil, pe, rt
	}
	return collectFrames(t, out), nil, rt
}

func streamMaskBlockedEntries(rt *trace.RequestTrace) []*appplugins.NativeMaskData {
	var out []*appplugins.NativeMaskData
	for _, span := range rt.Spans() {
		if span.Type != trace.SpanPlugin || span.Name != appplugins.BedrockNativePassthrough {
			continue
		}
		attrs := span.PluginAttrsCopy()
		if data, ok := attrs.Extras.(*appplugins.NativeMaskData); ok && attrs.Decision == "block" {
			out = append(out, data)
		}
	}
	return out
}

// requireStreamMaskBlocked is what a mask a stream cannot apply looks like: the
// stream ends where the held text began, with the exception the dialect has for a
// refused call (or a 403 before the first byte), the frames that were already
// released untouched, and one blocked entry for the cause with the streamed marker.
func requireStreamMaskBlocked(t *testing.T, got [][]byte, pe *appplugins.PluginError, frames [][]byte, rt *trace.RequestTrace, cause string) {
	t.Helper()
	if pe != nil {
		assert.Equal(t, 403, pe.StatusCode)
		assert.Equal(t, appplugins.BedrockNativePassthrough, pe.Type)
	} else {
		require.NotEmpty(t, got)
		excType, _ := decodeException(t, got[len(got)-1])
		assert.Equal(t, "validationException", excType)
		released := got[:len(got)-1]
		require.Less(t, len(released), len(frames), "the held frames were dropped, not released")
		assert.Equal(t, frames[:len(released)], released, "what was already released is untouched")
	}
	var causes []string
	for _, e := range streamMaskBlockedEntries(rt) {
		assert.Equal(t, appplugins.DecisionBlocked, e.Decision)
		assert.Equal(t, "pre_response", e.Stage)
		assert.True(t, e.Streamed)
		assert.True(t, e.Degraded)
		causes = append(causes, e.FailureReason)
	}
	assert.Contains(t, causes, "mask_not_applicable:"+cause)
	seen := map[string]int{}
	for _, c := range causes {
		seen[c]++
		assert.Equal(t, 1, seen[c], "one entry per kind of cause per stream: %s", c)
	}
}

// newTextMaskRunner masks from only in the text a segment adds, as a rewriting
// plugin that works from the offset of the new block does.
type newTextMaskRunner struct{ from, to string }

func (r *newTextMaskRunner) RunStreamSegment(_ context.Context, _ appplugins.StageInput, seg appplugins.StreamSegment) (*appplugins.SegmentOutcome, error) {
	if seg.Closing || !strings.Contains(seg.Text, r.from) {
		return &appplugins.SegmentOutcome{}, nil
	}
	head := seg.Accumulated[:len(seg.Accumulated)-len(seg.Text)]
	return &appplugins.SegmentOutcome{HasTransform: true, Transformed: head + strings.ReplaceAll(seg.Text, r.from, r.to)}, nil
}

// A mask a stream cannot apply ends it: the held frames are dropped, never
// released with the text the policy asked to mask, and the stream closes with the
// exception the dialect has for a refused call. The cause is recorded once.
func TestNativeStreamGuard_AMaskThatCannotBeAppliedEndsTheStream(t *testing.T) {
	t.Parallel()
	frames := [][]byte{
		deltaFrame(t, "Hello there friend"),
		testEventFrame(t, "contentBlockDelta", `{"contentBlockIndex":0,"delta":{"reasoningContent":{"text":"thinking"}}}`),
		deltaFrame(t, " first write to "+streamEmail+" now"),
		deltaFrame(t, " later write to "+streamEmail+" again"),
		deltaFrame(t, " and bye"),
	}
	g := nativeGuardFor(&newTextMaskRunner{from: streamEmail, to: "<EMAIL>"}, streamGuardConfig{headChars: 5, minChars: 30, maxHold: time.Hour})
	got, pe, rt := runNativeGuardTraced(t, g, frames)
	requireStreamMaskBlocked(t, got, pe, frames, rt, "reasoning_not_maskable")
	if pe == nil {
		assert.NotContains(t, releasedText(t, got[:len(got)-1]), streamEmail)
	}
}
