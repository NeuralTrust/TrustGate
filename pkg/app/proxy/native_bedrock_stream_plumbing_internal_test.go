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
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var plumbingEmailRE = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)

// regexMaskRunner masks every match of an email pattern, as a regex policy
// does: unlike an exact-string runner it takes whatever precedes the address
// in the text it is shown, glued to it or not, into the match.
type regexMaskRunner struct{}

func (regexMaskRunner) RunStreamSegment(_ context.Context, _ appplugins.StageInput, seg appplugins.StreamSegment) (*appplugins.SegmentOutcome, error) {
	if seg.Closing || !plumbingEmailRE.MatchString(seg.Accumulated) {
		return &appplugins.SegmentOutcome{}, nil
	}
	return &appplugins.SegmentOutcome{HasTransform: true, Transformed: plumbingEmailRE.ReplaceAllString(seg.Accumulated, "[MASKED_EMAIL]")}, nil
}

var spanningMaskRE = regexp.MustCompile(`standard\s+jane\.doe@example\.com`)

// spanningMaskRunner masks a pattern that reads across a line break, the one
// way a match can still run from text no delta wrote into a delta.
type spanningMaskRunner struct{}

func (spanningMaskRunner) RunStreamSegment(_ context.Context, _ appplugins.StageInput, seg appplugins.StreamSegment) (*appplugins.SegmentOutcome, error) {
	if seg.Closing || !spanningMaskRE.MatchString(seg.Accumulated) {
		return &appplugins.SegmentOutcome{}, nil
	}
	return &appplugins.SegmentOutcome{HasTransform: true, Transformed: spanningMaskRE.ReplaceAllString(seg.Accumulated, "[MASKED]")}, nil
}

func invokeChunkInner(t *testing.T, frame []byte) string {
	t.Helper()
	var holder struct {
		Bytes string `json:"bytes"`
	}
	require.NoError(t, json.Unmarshal([]byte(decodeFrameText(t, frame)), &holder))
	raw, err := base64.StdEncoding.DecodeString(holder.Bytes)
	require.NoError(t, err)
	return string(raw)
}

func anthropicInvokeTextStream(t *testing.T, messageStartExtra string, pieces ...string) [][]byte {
	t.Helper()
	frames := [][]byte{
		chunkFrame(t, `{"type":"message_start","message":{"model":"claude-haiku-4-5-20251001","id":"msg_bdrk_01X","type":"message","role":"assistant","content":[],"stop_reason":null,"stop_sequence":null`+messageStartExtra+`,"usage":{"input_tokens":20,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":1,"service_tier":"standard"}}}`),
		chunkFrame(t, `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`),
	}
	for _, p := range pieces {
		frames = append(frames, chunkFrame(t, `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":`+jsonString(p)+`}}`))
	}
	return append(frames,
		chunkFrame(t, `{"type":"content_block_stop","index":0}`),
		chunkFrame(t, `{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":12}}`),
		chunkFrame(t, `{"type":"message_stop","amazon-bedrock-invocationMetrics":{"inputTokenCount":20,"outputTokenCount":12,"invocationLatency":900,"firstByteLatency":400}}`))
}

func textDeltas(t *testing.T, frames [][]byte) string {
	t.Helper()
	var out strings.Builder
	for _, f := range frames {
		var ev struct {
			Type  string `json:"type"`
			Delta struct {
				Text string `json:"text"`
			} `json:"delta"`
		}
		if json.Unmarshal([]byte(invokeChunkInner(t, f)), &ev) == nil && ev.Type == "content_block_delta" {
			out.WriteString(ev.Delta.Text)
		}
	}
	return out.String()
}

// The service tier in message_start is a label, not text: it must not be glued
// to the first delta, or a regex match would take it in and the whole mask would
// land in message_start while every delta was emptied.
func TestNativeStream_AnthropicInvokeMaskLandsInTheDeltasNotInMessageStart(t *testing.T) {
	t.Parallel()
	for name, pieces := range map[string][]string{
		"one delta":      {"jane.doe@example.com"},
		"split deltas":   {"jane", ".doe", "@example", ".com"},
		"around the tld": {"Write to jane.doe@", "example.com now"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			frames := anthropicInvokeTextStream(t, "", pieces...)
			got, pe, rt := runNativeGuardTraced(t, nativeGuardFor(regexMaskRunner{}, streamGuardConfig{}), frames)
			require.Nil(t, pe)
			require.Len(t, got, len(frames))
			assert.Empty(t, streamFailedOpenEntries(rt))
			assert.Equal(t, frames[0], got[0], "message_start is released byte for byte")
			released := textDeltas(t, got)
			assert.Contains(t, released, "[MASKED_EMAIL]")
			assert.NotContains(t, released, "jane.doe")
			assert.NotContains(t, released, "example.com")
			assert.Equal(t, strings.Join(pieces, ""), strings.Replace(released, "[MASKED_EMAIL]", "jane.doe@example.com", 1))
		})
	}
}

// A frame can carry text a delta did not write, and a match that runs from it
// into a delta has no honest place to land: the mask fails open, flagged,
// rather than empty the deltas.
func TestNativeStream_MaskSpanningPlumbingTextFailsOpen(t *testing.T) {
	t.Parallel()
	// The "note" field is synthetic, and the pattern reads across the line break
	// that fences it: the guard is pinned with a constructed spanning case.
	frames := anthropicInvokeTextStream(t, `,"note":"standard"`, "jane", ".doe", "@example", ".com")
	got, pe, rt := runNativeGuardTraced(t, nativeGuardFor(spanningMaskRunner{}, streamGuardConfig{}), frames)
	require.Nil(t, pe)
	requireStreamFailedOpen(t, got, frames, rt, string(adapter.MaskCauseGluedText))
	assert.Equal(t, "jane.doe@example.com", textDeltas(t, got), "the text is released whole, never emptied")
}

// message_delta reports the stop sequence the model ended on. It is a label, not
// text, so a mask on the address the last delta ends with must still land.
func TestNativeStream_StopSequenceIsNotGluedToTheLastDelta(t *testing.T) {
	t.Parallel()
	for name, pieces := range map[string][]string{
		"one delta":    {"Mail bob@example.com"},
		"split deltas": {"Mail bob", "@example", ".com"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			frames := anthropicInvokeTextStream(t, "", pieces...)
			stop := len(frames) - 2
			frames[stop] = chunkFrame(t, `{"type":"message_delta","delta":{"stop_reason":"stop_sequence","stop_sequence":"END"},"usage":{"output_tokens":12}}`)
			got, pe, rt := runNativeGuardTraced(t, nativeGuardFor(regexMaskRunner{}, streamGuardConfig{}), frames)
			require.Nil(t, pe)
			require.Len(t, got, len(frames))
			assert.Empty(t, streamFailedOpenEntries(rt))
			assert.Equal(t, frames[stop], got[stop], "message_delta is released byte for byte")
			released := textDeltas(t, got)
			assert.Contains(t, released, "[MASKED_EMAIL]")
			assert.NotContains(t, released, "bob")
			assert.NotContains(t, released, "example.com")
		})
	}
}

// A citation carries the quoted source text beside the model's own text. It is
// not text the model wrote in a delta, so a mask on the address the delta ends
// with must not take the quotation into its match.
func TestNativeStream_CitedTextIsNotGluedToTheLastDelta(t *testing.T) {
	t.Parallel()
	frames := anthropicInvokeTextStream(t, "", "Mail bob", "@example", ".com")
	at := len(frames) - 3
	cite := chunkFrame(t, `{"type":"content_block_delta","index":0,"delta":{"type":"citations_delta","citation":{"type":"char_location","cited_text":"Source quote","document_index":0,"document_title":"Doc","start_char_index":0,"end_char_index":12}}}`)
	frames = append(frames[:at+1], append([][]byte{cite}, frames[at+1:]...)...)
	got, pe, rt := runNativeGuardTraced(t, nativeGuardFor(regexMaskRunner{}, streamGuardConfig{}), frames)
	require.Nil(t, pe)
	require.Len(t, got, len(frames))
	assert.Empty(t, streamFailedOpenEntries(rt))
	assert.Equal(t, cite, got[at+1], "the citation is released byte for byte")
	released := textDeltas(t, got)
	assert.Contains(t, released, "[MASKED_EMAIL]")
	assert.NotContains(t, released, "bob")
}
