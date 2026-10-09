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

func streamFailedOpenEntries(rt *trace.RequestTrace) []*appplugins.NativeMaskData {
	var out []*appplugins.NativeMaskData
	for _, span := range rt.Spans() {
		if span.Type != trace.SpanPlugin || span.Name != appplugins.BedrockNativePassthrough {
			continue
		}
		attrs := span.PluginAttrsCopy()
		if data, ok := attrs.Extras.(*appplugins.NativeMaskData); ok && attrs.Decision == appplugins.DecisionFailedOpen {
			out = append(out, data)
		}
	}
	return out
}

// requireStreamFailedOpen is what a mask a stream cannot apply now looks like:
// no cut, every frame released as it came, and one failed-open entry for the
// cause with the streamed marker.
func requireStreamFailedOpen(t *testing.T, got, frames [][]byte, rt *trace.RequestTrace, cause string) {
	t.Helper()
	assert.Equal(t, frames, got, "the frames go through as they came and the stream is not cut")
	var causes []string
	for _, e := range streamFailedOpenEntries(rt) {
		assert.Equal(t, appplugins.DecisionFailedOpen, e.Decision)
		assert.Equal(t, "pre_response", e.Stage)
		assert.True(t, e.Streamed)
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

// A mask a stream cannot apply does not end the inspection: the next block is
// inspected as usual, and a mask it can apply is applied.
func TestNativeStreamGuard_FailOpenKeepsInspectingLaterBlocks(t *testing.T) {
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
	require.Nil(t, pe)
	require.Len(t, got, len(frames))
	assert.Equal(t, frames[:3], got[:3], "the block the mask could not be applied to is released as it came")
	assert.Contains(t, decodeFrameText(t, got[3]), "<EMAIL>", "the next block is inspected and masked")
	assert.NotContains(t, decodeFrameText(t, got[3]), streamEmail)
	entries := streamFailedOpenEntries(rt)
	require.Len(t, entries, 1)
	assert.Equal(t, "mask_not_applicable:reasoning_not_maskable", entries[0].FailureReason)
}

// An explicit block verdict still ends the stream.
func TestNativeStreamGuard_ABlockVerdictStillBlocksAfterAFailOpen(t *testing.T) {
	t.Parallel()
	frames := [][]byte{
		deltaFrame(t, "Hello there friend"),
		testEventFrame(t, "contentBlockDelta", `{"contentBlockIndex":0,"delta":{"reasoningContent":{"text":"thinking"}}}`),
		deltaFrame(t, " write to "+streamEmail+" now"),
		deltaFrame(t, " forbidden words here"),
	}
	g := nativeGuardFor(&blockAfterMaskRunner{mask: &newTextMaskRunner{from: streamEmail, to: "<EMAIL>"}, needle: "forbidden"}, streamGuardConfig{headChars: 5, minChars: 30, maxHold: time.Hour})
	got, pe, rt := runNativeGuardTraced(t, g, frames)
	require.Nil(t, pe)
	excType, _ := decodeException(t, got[len(got)-1])
	assert.Equal(t, "validationException", excType)
	assert.Len(t, streamFailedOpenEntries(rt), 1, "the earlier fail-open is still recorded")
}

type blockAfterMaskRunner struct {
	mask   *newTextMaskRunner
	needle string
}

func (r *blockAfterMaskRunner) RunStreamSegment(ctx context.Context, in appplugins.StageInput, seg appplugins.StreamSegment) (*appplugins.SegmentOutcome, error) {
	if !seg.Closing && strings.Contains(seg.Text, r.needle) {
		return &appplugins.SegmentOutcome{Block: true, Type: "blocked", Message: "no"}, nil
	}
	return r.mask.RunStreamSegment(ctx, in, seg)
}
