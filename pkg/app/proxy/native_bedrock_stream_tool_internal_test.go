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
	"encoding/json"
	"iter"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// textOnlyMaskRunner is a policy that reads text and never a tool input: a
// segment that is a JSON document is let through.
type textOnlyMaskRunner struct{ maskRunner }

func (r *textOnlyMaskRunner) RunStreamSegment(ctx context.Context, in appplugins.StageInput, seg appplugins.StreamSegment) (*appplugins.SegmentOutcome, error) {
	if strings.HasPrefix(strings.TrimSpace(seg.Accumulated), "{") {
		return &appplugins.SegmentOutcome{}, nil
	}
	return r.maskRunner.RunStreamSegment(ctx, in, seg)
}

// blockRunner blocks any segment that holds needle.
type blockRunner struct{ needle string }

func (r *blockRunner) RunStreamSegment(_ context.Context, _ appplugins.StageInput, seg appplugins.StreamSegment) (*appplugins.SegmentOutcome, error) {
	if !seg.Closing && strings.Contains(seg.Accumulated, r.needle) {
		return &appplugins.SegmentOutcome{Block: true, Type: "blocked", Message: "no"}, nil
	}
	return &appplugins.SegmentOutcome{}, nil
}

// firstMaskRunner masks the first occurrence of from in the text of a segment
// that is not a tool input: a policy that found the value in one place only.
type firstMaskRunner struct{ from, to string }

func (r *firstMaskRunner) RunStreamSegment(_ context.Context, _ appplugins.StageInput, seg appplugins.StreamSegment) (*appplugins.SegmentOutcome, error) {
	if seg.Closing || strings.HasPrefix(strings.TrimSpace(seg.Accumulated), "{") || !strings.Contains(seg.Accumulated, r.from) {
		return &appplugins.SegmentOutcome{}, nil
	}
	return &appplugins.SegmentOutcome{HasTransform: true, Transformed: strings.Replace(seg.Accumulated, r.from, r.to, 1)}, nil
}

var toolBlocks = streamGuardConfig{headChars: 5, minChars: 1, maxHold: time.Hour}

func converseToolFrames(t *testing.T, index int, fragments ...string) [][]byte {
	t.Helper()
	frames := [][]byte{testEventFrame(t, "contentBlockStart",
		`{"contentBlockIndex":`+itoa(index)+`,"start":{"toolUse":{"toolUseId":"tooluse_abc","name":"send_mail"}}}`)}
	for _, f := range fragments {
		frames = append(frames, testEventFrame(t, "contentBlockDelta",
			`{"contentBlockIndex":`+itoa(index)+`,"delta":{"toolUse":{"input":`+jsonString(f)+`}}}`))
	}
	return append(frames, testEventFrame(t, "contentBlockStop", `{"contentBlockIndex":`+itoa(index)+`}`))
}

func anthropicToolFrames(t *testing.T, index int, fragments ...string) [][]byte {
	t.Helper()
	frames := [][]byte{chunkFrame(t, `{"type":"content_block_start","index":`+itoa(index)+
		`,"content_block":{"type":"tool_use","id":"toolu_01","name":"send_mail","input":{}}}`)}
	for _, f := range fragments {
		frames = append(frames, chunkFrame(t, `{"type":"content_block_delta","index":`+itoa(index)+
			`,"delta":{"type":"input_json_delta","partial_json":`+jsonString(f)+`}}`))
	}
	return append(frames, chunkFrame(t, `{"type":"content_block_stop","index":`+itoa(index)+`}`))
}

func itoa(i int) string { return string(rune('0' + i)) }

// fragmentsOf is the tool input fragment of every frame that carries one.
func fragmentsOf(frames [][]byte) []string {
	var out []string
	for _, f := range frames {
		if in, ok := adapter.BedrockFrameToolInput(f); ok {
			out = append(out, in)
		}
	}
	return out
}

func TestNativeToolMask_ConverseEmailSplitAcrossFragments(t *testing.T) {
	t.Parallel()
	tool := converseToolFrames(t, 1, `{"to":"bo`, `b@x`, `.io","subject":"hi"}`)
	frames := append(append([][]byte{
		testEventFrame(t, "messageStart", `{"role":"assistant"}`),
		deltaFrame(t, "Sending it now"),
	}, tool...), testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))

	runner := &maskRunner{from: streamEmail, to: "<EMAIL>"}
	got, pe := runNativeGuard(t, nativeGuardFor(runner, toolBlocks), frames)
	require.Nil(t, pe)
	require.Len(t, got, len(frames), "no frame is dropped: the ones left empty stay as valid frames")

	for _, f := range got {
		decodeFrameText(t, f) // prelude, length and both checksums
	}
	assert.Equal(t, tool[0], got[2], "toolUseId and name are the start frame as it came")
	assert.Equal(t, tool[len(tool)-1], got[len(got)-2], "the stop frame is as it came")

	fragments := fragmentsOf(got)
	require.Len(t, fragments, 3)
	assert.Equal(t, `{"to":"<EMAIL>","subject":"hi"}`, fragments[0], "the whole masked input is in the first fragment")
	assert.Empty(t, fragments[1])
	assert.Empty(t, fragments[2])

	var parsed map[string]string
	require.NoError(t, json.Unmarshal([]byte(strings.Join(fragments, "")), &parsed), "an SDK parses the joined input")
	assert.Equal(t, map[string]string{"to": "<EMAIL>", "subject": "hi"}, parsed)
	assert.NotContains(t, releasedText(t, got), streamEmail)
	assert.NotContains(t, releasedText(t, got), "b@x")
	assert.Equal(t, frames[0], got[0])
	assert.Equal(t, frames[1], got[1], "the text before the call is as it came")
}

func TestNativeToolMask_AnthropicInvokeEmailSplitAcrossFragments(t *testing.T) {
	t.Parallel()
	tool := anthropicToolFrames(t, 1, `{"to":"b`, `ob@x.i`, `o"}`)
	frames := append(append([][]byte{
		chunkFrame(t, `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Sending it now"}}`),
	}, tool...), chunkFrame(t, `{"type":"message_delta","delta":{"stop_reason":"tool_use"}}`))

	runner := &maskRunner{from: streamEmail, to: "<EMAIL>"}
	got, pe := runNativeGuard(t, nativeGuardFor(runner, toolBlocks), frames)
	require.Nil(t, pe)
	require.Len(t, got, len(frames))
	assert.Equal(t, tool[0], got[1], "the id and the name are the start chunk as it came")
	assert.Equal(t, tool[len(tool)-1], got[len(got)-2])

	fragments := fragmentsOf(got)
	require.Len(t, fragments, 3)
	assert.Equal(t, `{"to":"<EMAIL>"}`, fragments[0])
	assert.Empty(t, fragments[1])
	assert.Empty(t, fragments[2])
	assert.NotContains(t, releasedText(t, got), streamEmail)
	// The chunk keeps the shape the SDK reads.
	view := string(adapter.BedrockFrameView(got[3])[0])
	assert.Contains(t, view, `"type":"input_json_delta"`)
	assert.Contains(t, view, `"index":1`)
}

func TestNativeToolMask_EscapedAtSignIsMasked(t *testing.T) {
	t.Parallel()
	for name, fragments := range map[string][]string{
		"escape inside the tool JSON":          {`{"to":"bob\u00`, `40x.io"}`},
		"escape inside the frame JSON only":    {"{\"to\":\"bob@", `x.io"}`},
		"escaped quote and slash around email": {`{"note":"say \"hi\" to bob@x.io \/ now"}`},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			frames := append([][]byte{deltaFrame(t, "Sending it now")}, converseToolFrames(t, 1, fragments...)...)
			frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))
			runner := &maskRunner{from: streamEmail, to: "<EMAIL>"}
			got, pe := runNativeGuard(t, nativeGuardFor(runner, toolBlocks), frames)
			require.Nil(t, pe)
			joined := strings.Join(fragmentsOf(got), "")
			var parsed map[string]string
			require.NoError(t, json.Unmarshal([]byte(joined), &parsed), joined)
			for _, v := range parsed {
				assert.Contains(t, v, "<EMAIL>")
			}
			assert.NotContains(t, releasedText(t, got), "x.io")
		})
	}
}

func TestNativeToolMask_MaskTouchingANumberFailsOpen(t *testing.T) {
	t.Parallel()
	frames := append([][]byte{deltaFrame(t, "Calling now")}, converseToolFrames(t, 1, `{"phone":415`, `5550123,"ok":true}`)...)
	frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))
	runner := &maskRunner{from: "4155550123", to: "<PHONE>"}
	got, pe, rt := runNativeGuardTraced(t, nativeGuardFor(runner, toolBlocks), frames)
	require.Nil(t, pe)
	requireStreamFailedOpen(t, got, frames, rt, "tool_input_not_maskable")
}

func TestNativeToolMask_InvalidToolInputFailsOpen(t *testing.T) {
	t.Parallel()
	frames := append([][]byte{deltaFrame(t, "Calling now")}, converseToolFrames(t, 1, `{"to":"bob@x`, `.io"`)...) // never closed
	frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))
	runner := &maskRunner{from: "bob@x", to: "<M>"}
	got, pe, rt := runNativeGuardTraced(t, nativeGuardFor(runner, toolBlocks), frames)
	require.Nil(t, pe)
	requireStreamFailedOpen(t, got, frames, rt, "tool_input_not_maskable")
}

func TestNativeToolMask_TextAndToolInTheSameWindow(t *testing.T) {
	t.Parallel()
	for name, build := range map[string]func() [][]byte{
		"converse": func() [][]byte {
			f := [][]byte{testEventFrame(t, "messageStart", `{"role":"assistant"}`), deltaFrame(t, "Hello there"),
				deltaFrame(t, "I will write to "+streamEmail+" now")}
			f = append(f, testEventFrame(t, "contentBlockStop", `{"contentBlockIndex":0}`))
			f = append(f, converseToolFrames(t, 1, `{"to":"bob@`, `x.io"}`)...)
			return append(f, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))
		},
		"anthropic invoke": func() [][]byte {
			f := [][]byte{
				chunkFrame(t, `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello there"}}`),
				chunkFrame(t, `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"I will write to `+streamEmail+` now"}}`),
				chunkFrame(t, `{"type":"content_block_stop","index":0}`)}
			f = append(f, anthropicToolFrames(t, 1, `{"to":"bob@`, `x.io"}`)...)
			return append(f, chunkFrame(t, `{"type":"message_delta","delta":{"stop_reason":"tool_use"}}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			frames := build()
			runner := &maskRunner{from: streamEmail, to: "<EMAIL>"}
			got, pe := runNativeGuard(t, nativeGuardFor(runner, streamGuardConfig{headChars: 5, minChars: 1000, maxHold: time.Hour}), frames)
			require.Nil(t, pe)
			require.Len(t, got, len(frames))
			released := releasedText(t, got)
			assert.NotContains(t, released, streamEmail)
			assert.Contains(t, released, "I will write to <EMAIL> now", "the text of the window is masked")
			fragments := fragmentsOf(got)
			require.NotEmpty(t, fragments)
			assert.Equal(t, `{"to":"<EMAIL>"}`, fragments[0], "and so is the tool input")
		})
	}
}

// The tool input is seen by the policy as a text of its own, so a policy that
// blocks on it ends the stream.
func TestNativeToolMask_ABlockOnToolInputEndsTheStream(t *testing.T) {
	t.Parallel()
	frames := append([][]byte{deltaFrame(t, "Running it")}, converseToolFrames(t, 1, `{"cmd":"rm `, `-rf /"}`)...)
	frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))
	got, pe := runNativeGuard(t, nativeGuardFor(&blockRunner{needle: "rm -rf"}, toolBlocks), frames)
	require.Nil(t, pe)
	excType, _ := decodeException(t, got[len(got)-1])
	assert.Equal(t, "validationException", excType)
	assert.Empty(t, fragmentsOf(got[:len(got)-1]), "no fragment of the call was released")
}

func TestNativeToolMask_CleanCallIsReleasedByteForByteAndWasInspected(t *testing.T) {
	t.Parallel()
	frames := append([][]byte{deltaFrame(t, "Sending it now")}, converseToolFrames(t, 1, `{"to":"someone`, `","n":42}`)...)
	frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))
	runner := &sequenceRunner{}
	got, pe := runNativeGuard(t, nativeGuardFor(runner, toolBlocks), frames)
	require.Nil(t, pe)
	assert.Equal(t, frames, got)
	assert.Contains(t, runner.texts, `{"to":"someone","n":42}`, "the policy was handed the joined tool input")
}

// A call is held from its start frame to its stop frame, and the text around it
// keeps the release behaviour it has.
func TestNativeToolMask_HoldsTheCallUntilItsStopAndNotTheTextAroundIt(t *testing.T) {
	t.Parallel()
	frames := append([][]byte{
		testEventFrame(t, "messageStart", `{"role":"assistant"}`),
		deltaFrame(t, "Hello there"),
		deltaFrame(t, "Sending it now"),
	}, converseToolFrames(t, 1, `{"a":`, `"b"`, `}`)...)
	frames = append(frames, deltaFrame(t, "Done"), testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))

	var pulled atomic.Int32
	src := func(yield func([]byte, error) bool) {
		for _, f := range frames {
			pulled.Add(1)
			if !yield(f, nil) {
				return
			}
		}
	}
	g := nativeGuardFor(&sequenceRunner{}, toolBlocks)
	out, pe := g.Run(context.Background(), iter.Seq2[[]byte, error](src))
	require.Nil(t, pe)
	var at []int32
	for range out {
		at = append(at, pulled.Load())
	}
	require.Len(t, at, len(frames))
	toolStart, toolStop := 3, 3+1+3 // the start frame and the stop frame of the call
	assert.Less(t, int(at[2]), toolStart+1, "the text before the call is released before the call starts")
	assert.GreaterOrEqual(t, int(at[toolStart]), toolStop+1, "the first frame of the call leaves only once its stop has arrived")
}

// A call that outgrows the hold before its stop frame is not edited: a mask on
// the same window cuts, as it did before calls were held.
func TestNativeToolMask_CallThatOutgrowsTheHoldFailsOpenOnAMask(t *testing.T) {
	t.Parallel()
	frames := [][]byte{
		deltaFrame(t, "Hello there"),
		deltaFrame(t, "I will write to "+streamEmail+" now"),
	}
	frames = append(frames, converseToolFrames(t, 1, `{"to":"bob@`, `x.io"}`)...)
	frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))

	var late atomic.Bool
	base := time.Now()
	g := nativeGuardFor(&maskRunner{from: streamEmail, to: "<EMAIL>"}, streamGuardConfig{headChars: 5, minChars: 100000, maxHold: 100 * time.Millisecond})
	g.now = func() time.Time {
		if late.Load() {
			return base.Add(time.Hour)
		}
		return base
	}
	src := func(yield func([]byte, error) bool) {
		for i, f := range frames {
			if i == 4 { // the first fragment of the call: far past the hold
				late.Store(true)
			}
			if !yield(f, nil) {
				return
			}
		}
	}
	rt := trace.New("t", trace.Metadata{})
	out, pe := g.Run(trace.NewContext(context.Background(), rt), iter.Seq2[[]byte, error](src))
	require.Nil(t, pe)
	got := collectFrames(t, out)
	requireStreamFailedOpen(t, got, frames, rt, "tool_call_not_held")
}

// Another family's tool call is not understood, so a mask next to one cuts.
func TestNativeToolMask_UnhandledFamilyFailsOpen(t *testing.T) {
	t.Parallel()
	frames := [][]byte{
		chunkFrame(t, `{"choices":[{"index":0,"delta":{"content":"write to `+streamEmail+` now"}}]}`),
		chunkFrame(t, `{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"send","arguments":"{\"to\":\"someone\"}"}}]}}]}`),
		chunkFrame(t, `{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`),
	}
	got, pe, rt := runNativeGuardTraced(t, nativeGuardFor(&maskRunner{from: streamEmail, to: "<EMAIL>"},
		streamGuardConfig{headChars: 1000, minChars: 1000, maxHold: time.Hour}), frames)
	require.Nil(t, pe)
	requireStreamFailedOpen(t, got, frames, rt, "tool_call_not_held")
}

// A short value is masked where the policy found it in a stream, and a tool
// input that carries the same characters elsewhere does not stop it.
func TestNativeStreamGuard_ShortValueIsMaskedWhereThePolicyFoundIt(t *testing.T) {
	t.Parallel()
	t.Run("inside one frame", func(t *testing.T) {
		t.Parallel()
		frames := [][]byte{
			testEventFrame(t, "messageStart", `{"role":"assistant"}`),
			deltaFrame(t, "my pin is 42 ok"),
			deltaFrame(t, "order 42 shipped, total 142"),
			testEventFrame(t, "messageStop", `{"stopReason":"end_turn"}`),
		}
		got, pe := runNativeGuard(t, nativeGuardFor(&firstMaskRunner{from: "42", to: "##"},
			streamGuardConfig{headChars: 1000, minChars: 1000, maxHold: time.Hour}), frames)
		require.Nil(t, pe)
		require.Len(t, got, len(frames))
		assert.Contains(t, decodeFrameText(t, got[1]), "my pin is ## ok")
		assert.Equal(t, frames[2], got[2], "the same characters in another frame are left alone")
	})
	t.Run("split across two frames", func(t *testing.T) {
		t.Parallel()
		frames := [][]byte{
			testEventFrame(t, "messageStart", `{"role":"assistant"}`),
			deltaFrame(t, "your code is 4"),
			deltaFrame(t, "2, thanks. And 42 again"),
			testEventFrame(t, "messageStop", `{"stopReason":"end_turn"}`),
		}
		got, pe := runNativeGuard(t, nativeGuardFor(&firstMaskRunner{from: "42", to: "##"},
			streamGuardConfig{headChars: 1000, minChars: 1000, maxHold: time.Hour}), frames)
		require.Nil(t, pe)
		released := releasedText(t, got)
		assert.Contains(t, released, "your code is ##")
		assert.Contains(t, released, ", thanks. And 42 again")
	})
	t.Run("a tool input with the same characters does not stop it", func(t *testing.T) {
		t.Parallel()
		frames := append([][]byte{deltaFrame(t, "your code is 42 ok")}, converseToolFrames(t, 1, `{"n":42,`, `"id":"x-42"}`)...)
		frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))
		got, pe := runNativeGuard(t, nativeGuardFor(&firstMaskRunner{from: "42", to: "##"},
			streamGuardConfig{headChars: 1000, minChars: 1000, maxHold: time.Hour}), frames)
		require.Nil(t, pe)
		require.Len(t, got, len(frames))
		assert.Contains(t, decodeFrameText(t, got[0]), "your code is ## ok")
		assert.Equal(t, `{"n":42,"id":"x-42"}`, strings.Join(fragmentsOf(got), ""))
	})
}

// A call that opens the stream is in the head, which is held whole as well.
func TestNativeToolMask_CallInTheHeadIsHeldAndMasked(t *testing.T) {
	t.Parallel()
	frames := append([][]byte{testEventFrame(t, "messageStart", `{"role":"assistant"}`)},
		converseToolFrames(t, 0, `{"to":"bo`, `b@x`, `.io"}`)...)
	frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))
	got, pe := runNativeGuard(t, nativeGuardFor(&maskRunner{from: streamEmail, to: "<EMAIL>"}, toolBlocks), frames)
	require.Nil(t, pe)
	require.Len(t, got, len(frames))
	assert.Equal(t, `{"to":"<EMAIL>"}`, fragmentsOf(got)[0])
	assert.NotContains(t, releasedText(t, got), streamEmail)
}

// A rebuilt frame that does not read as the text the policy returned is not
// released, even when the removed text is too short to be looked for elsewhere:
// here the first string of the frame that equals it is not the one the view reads.
func TestNativeStreamGuard_ShortValueFrameThatDoesNotReadBackFailsOpen(t *testing.T) {
	t.Parallel()
	frames := [][]byte{
		testEventFrame(t, "messageStart", `{"role":"assistant"}`),
		testEventFrame(t, "contentBlockDelta", `{"aaa":"42","contentBlockIndex":0,"delta":{"text":"42"}}`),
		testEventFrame(t, "messageStop", `{"stopReason":"end_turn"}`),
	}
	got, pe, rt := runNativeGuardTraced(t, nativeGuardFor(&firstMaskRunner{from: "42", to: "##"},
		streamGuardConfig{headChars: 1000, minChars: 1000, maxHold: time.Hour}), frames)
	require.Nil(t, pe)
	requireStreamFailedOpen(t, got, frames, rt, "shape_mismatch")
}

// firstToolMaskRunner masks the first occurrence of from in a tool input only: a
// policy that leaves a second copy of the value behind.
type firstToolMaskRunner struct{ from, to string }

func (r *firstToolMaskRunner) RunStreamSegment(_ context.Context, _ appplugins.StageInput, seg appplugins.StreamSegment) (*appplugins.SegmentOutcome, error) {
	if seg.Closing || !strings.HasPrefix(strings.TrimSpace(seg.Accumulated), "{") || !strings.Contains(seg.Accumulated, r.from) {
		return &appplugins.SegmentOutcome{}, nil
	}
	return &appplugins.SegmentOutcome{HasTransform: true, Transformed: strings.Replace(seg.Accumulated, r.from, r.to, 1)}, nil
}

// A mask that leaves a copy of the removed text in the input is not released.
func TestNativeToolMask_AMaskThatLeavesACopyBehindFailsOpen(t *testing.T) {
	t.Parallel()
	frames := append([][]byte{deltaFrame(t, "Sending it now")}, converseToolFrames(t, 1, `{"a":"bob@x.io",`, `"b":"bob@x.io"}`)...)
	frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`))
	got, pe, rt := runNativeGuardTraced(t, nativeGuardFor(&firstToolMaskRunner{from: streamEmail, to: "<EMAIL>"}, toolBlocks), frames)
	require.Nil(t, pe)
	requireStreamFailedOpen(t, got, frames, rt, "tool_input_not_maskable")
}
