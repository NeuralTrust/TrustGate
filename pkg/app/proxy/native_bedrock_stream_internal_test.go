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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"iter"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	catalogmocks "github.com/NeuralTrust/TrustGate/pkg/app/catalog/mocks"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func testEventFrame(t *testing.T, eventType, payload string) []byte {
	t.Helper()
	var headers eventstream.Headers
	headers.Set(":message-type", eventstream.StringValue("event"))
	headers.Set(":event-type", eventstream.StringValue(eventType))
	headers.Set(":content-type", eventstream.StringValue("application/json"))
	var buf bytes.Buffer
	require.NoError(t, eventstream.NewEncoder().Encode(&buf, eventstream.Message{Headers: headers, Payload: []byte(payload)}))
	return buf.Bytes()
}

// textFrames is a ConverseStream: a start, one text delta per word, a stop and
// the usage metadata.
func textFrames(t *testing.T, words ...string) [][]byte {
	t.Helper()
	frames := [][]byte{testEventFrame(t, "messageStart", `{"role":"assistant"}`)}
	for _, w := range words {
		frames = append(frames, testEventFrame(t, "contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":"`+w+`"}}`))
	}
	frames = append(frames,
		testEventFrame(t, "messageStop", `{"stopReason":"end_turn"}`),
		testEventFrame(t, "metadata", `{"usage":{"inputTokens":3,"outputTokens":4,"totalTokens":7}}`),
	)
	return frames
}

func frameSeq(frames [][]byte) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		for _, f := range frames {
			if !yield(f, nil) {
				return
			}
		}
	}
}

func collectFrames(t *testing.T, seq iter.Seq2[[]byte, error]) [][]byte {
	t.Helper()
	var out [][]byte
	for item, err := range seq {
		require.NoError(t, err)
		out = append(out, item)
	}
	return out
}

// sequenceRunner answers each guard call with the next scripted verdict.
type sequenceRunner struct {
	outcomes []*appplugins.SegmentOutcome
	err      error
	calls    int
	texts    []string
}

func (r *sequenceRunner) RunStreamSegment(
	_ context.Context,
	_ appplugins.StageInput,
	seg appplugins.StreamSegment,
) (*appplugins.SegmentOutcome, error) {
	if seg.Closing {
		return &appplugins.SegmentOutcome{}, nil
	}
	r.texts = append(r.texts, seg.Accumulated)
	i := r.calls
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	if i < len(r.outcomes) {
		return r.outcomes[i], nil
	}
	return &appplugins.SegmentOutcome{}, nil
}

func nativeGuardFor(runner segmentRunner, cfg streamGuardConfig) *streamGuard {
	g := newStreamGuard(runner, adapter.NewRegistry(), adapter.FormatBedrockNative, stageInputFixture(), cfg, newGuardLogger())
	g.native = true
	g.seg.frames = true
	return g
}

// run drives the guard the way finalizeStream does: the head verdict first,
// then the block loop over the rest.
func runNativeGuard(t *testing.T, g *streamGuard, frames [][]byte) ([][]byte, *appplugins.PluginError) {
	t.Helper()
	out, pe := g.Run(context.Background(), frameSeq(frames))
	if pe != nil {
		return nil, pe
	}
	return collectFrames(t, out), nil
}

func decodeException(t *testing.T, frame []byte) (string, string) {
	t.Helper()
	msg, err := eventstream.NewDecoder().Decode(bytes.NewReader(frame), nil)
	require.NoError(t, err, "the cut must be a well-formed eventstream frame")
	require.Equal(t, "exception", msg.Headers.Get(":message-type").String())
	return msg.Headers.Get(":exception-type").String(), string(msg.Payload)
}

var fastBlocks = streamGuardConfig{headChars: 5, minChars: 1, maxHold: time.Hour}

func TestNativeStreamGuard_CleanStreamIsRelayedByteIdentical(t *testing.T) {
	t.Parallel()
	frames := textFrames(t, "Hello", " there", " friend", " how", " are", " you")
	runner := &sequenceRunner{}
	got, pe := runNativeGuard(t, nativeGuardFor(runner, fastBlocks), frames)
	require.Nil(t, pe)
	assert.Equal(t, frames, got, "every frame, in order, byte for byte")
	assert.Greater(t, runner.calls, 1, "the text was inspected block by block")
	assert.Contains(t, runner.texts[len(runner.texts)-1], "Hello there friend how are you")
}

func TestNativeStreamGuard_InvokeChunksAreInspectedAndRelayed(t *testing.T) {
	t.Parallel()
	chunk := func(text string) []byte {
		// The model's own JSON, base64 encoded as Bedrock sends it. The hidden
		// text sits under a second key the family decoders do not read.
		inner := `{"outputText":"` + text + `","other":"HIDDEN"}`
		return testEventFrame(t, "chunk", `{"bytes":"`+b64(inner)+`"}`)
	}
	frames := [][]byte{chunk("Hello world")}
	runner := &sequenceRunner{}
	g := nativeGuardFor(runner, fastBlocks)
	got, pe := runNativeGuard(t, g, frames)
	require.Nil(t, pe)
	assert.Equal(t, frames, got)
	require.NotEmpty(t, runner.texts)
	assert.Contains(t, runner.texts[0], "Hello world")
	assert.Contains(t, runner.texts[0], "HIDDEN", "the union principle holds on stream chunks")
}

func TestNativeStreamGuard_BlockInTheHeadIsAStatusNotAFrame(t *testing.T) {
	t.Parallel()
	frames := textFrames(t, "Hello", " world")
	runner := &sequenceRunner{outcomes: []*appplugins.SegmentOutcome{{Block: true, Type: "guardrail_blocked", Message: "nope"}}}
	got, pe := runNativeGuard(t, nativeGuardFor(runner, fastBlocks), frames)
	require.NotNil(t, pe, "before any byte went out the block is still a real HTTP status")
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
	assert.Equal(t, "guardrail_blocked", pe.Type)
	assert.Empty(t, got)
}

func TestNativeStreamGuard_BlockMidStreamEmitsAnExceptionFrameAndStops(t *testing.T) {
	t.Parallel()
	frames := textFrames(t, "Hello", " clean", " BAD", " later", " still", " more")
	// The first block clears, the second carries the offending text.
	runner := &sequenceRunner{outcomes: []*appplugins.SegmentOutcome{
		{}, {Block: true, Type: "guardrail_blocked", Message: "blocked by policy"},
	}}
	got, pe := runNativeGuard(t, nativeGuardFor(runner, fastBlocks), frames)
	require.Nil(t, pe)
	require.NotEmpty(t, got)

	last := got[len(got)-1]
	excType, payload := decodeException(t, last)
	assert.Equal(t, "validationException", excType)
	assert.Contains(t, payload, "blocked by policy")
	assert.Contains(t, payload, "guardrail_blocked")

	released := got[:len(got)-1]
	assert.Equal(t, frames[:len(released)], released, "what was relayed before the cut is byte-identical")
	for _, f := range got {
		assert.False(t, bytes.Equal(f, frames[len(frames)-1]), "nothing after the cut reaches the client")
	}
	// The offending segment is never released.
	badFrame := frames[3]
	for _, f := range released {
		assert.False(t, bytes.Equal(f, badFrame), "the segment the verdict blocked must be held back")
	}
}

// maskRunner masks `from` wherever the accumulated text holds it, which is what a
// masking plugin hands back: the whole accumulated text, rewritten.
type maskRunner struct {
	from, to string
	calls    int
}

func (r *maskRunner) RunStreamSegment(
	_ context.Context,
	_ appplugins.StageInput,
	seg appplugins.StreamSegment,
) (*appplugins.SegmentOutcome, error) {
	if seg.Closing {
		return &appplugins.SegmentOutcome{}, nil
	}
	r.calls++
	if strings.Contains(seg.Accumulated, r.from) {
		return &appplugins.SegmentOutcome{HasTransform: true, Transformed: strings.ReplaceAll(seg.Accumulated, r.from, r.to)}, nil
	}
	return &appplugins.SegmentOutcome{}, nil
}

func decodeFrameText(t *testing.T, frame []byte) string {
	t.Helper()
	msg, err := eventstream.NewDecoder().Decode(bytes.NewReader(frame), nil)
	require.NoError(t, err, "a rebuilt frame must have a valid prelude, length and checksums")
	return string(msg.Payload)
}

func deltaFrame(t *testing.T, text string) []byte {
	t.Helper()
	return testEventFrame(t, "contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":`+jsonString(text)+`}}`)
}

func jsonString(s string) string {
	out, _ := json.Marshal(s)
	return string(out)
}

const streamEmail = "bob@x.io"

func joinedPayloads(t *testing.T, frames [][]byte) string {
	t.Helper()
	var sb strings.Builder
	for _, f := range frames {
		sb.WriteString(decodeFrameText(t, f))
	}
	return sb.String()
}

func TestNativeStreamGuard_MaskInsideOneFrame(t *testing.T) {
	t.Parallel()
	frames := [][]byte{
		testEventFrame(t, "messageStart", `{"role":"assistant"}`),
		deltaFrame(t, "Hello there"),
		deltaFrame(t, " write to "+streamEmail+" now"),
		deltaFrame(t, " and bye"),
		testEventFrame(t, "messageStop", `{"stopReason":"end_turn"}`),
		testEventFrame(t, "metadata", `{"usage":{"inputTokens":3,"outputTokens":4,"totalTokens":7}}`),
	}
	runner := &maskRunner{from: streamEmail, to: "<EMAIL>"}
	got, pe := runNativeGuard(t, nativeGuardFor(runner, streamGuardConfig{headChars: 5, minChars: 1000, maxHold: time.Hour}), frames)
	require.Nil(t, pe)
	require.Len(t, got, len(frames), "no frame is dropped")

	assert.NotContains(t, joinedPayloads(t, got), streamEmail)
	assert.Contains(t, decodeFrameText(t, got[2]), " write to <EMAIL> now")
	for i := range frames {
		if i == 2 {
			continue
		}
		assert.Equal(t, frames[i], got[i], "frame %d is not touched by the mask and is released byte for byte", i)
	}
	// The rebuilt frame keeps its headers.
	orig, err := eventstream.NewDecoder().Decode(bytes.NewReader(frames[2]), nil)
	require.NoError(t, err)
	rebuilt, err := eventstream.NewDecoder().Decode(bytes.NewReader(got[2]), nil)
	require.NoError(t, err)
	assert.Equal(t, orig.Headers, rebuilt.Headers)
}

func TestNativeStreamGuard_MaskSplitAcrossFrames(t *testing.T) {
	t.Parallel()
	for name, parts := range map[string][]string{
		"two frames":   {"write to bo", "b@x.io now"},
		"three frames": {"write to bo", "b@", "x.io now"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			frames := [][]byte{testEventFrame(t, "messageStart", `{"role":"assistant"}`)}
			for _, p := range parts {
				frames = append(frames, deltaFrame(t, p))
			}
			frames = append(frames, testEventFrame(t, "messageStop", `{"stopReason":"end_turn"}`))
			runner := &maskRunner{from: streamEmail, to: "<EMAIL>"}
			// One block holds the whole message, so the held window covers every part.
			got, pe := runNativeGuard(t, nativeGuardFor(runner, streamGuardConfig{headChars: 1000, minChars: 1000, maxHold: time.Hour}), frames)
			require.Nil(t, pe)
			require.Len(t, got, len(frames), "frames emptied by the mask are kept, not dropped")

			payloads := joinedPayloads(t, got)
			assert.NotContains(t, payloads, streamEmail)
			assert.Contains(t, decodeFrameText(t, got[1]), "<EMAIL>", "the whole replacement is in the first affected frame")
			var text strings.Builder
			for _, f := range got[1 : len(got)-1] {
				msg, err := eventstream.NewDecoder().Decode(bytes.NewReader(f), nil)
				require.NoError(t, err)
				var ev struct {
					Delta struct {
						Text string `json:"text"`
					} `json:"delta"`
				}
				require.NoError(t, json.Unmarshal(msg.Payload, &ev))
				text.WriteString(ev.Delta.Text)
			}
			assert.Equal(t, "write to <EMAIL> now", text.String())
			assert.Equal(t, frames[0], got[0])
			assert.Equal(t, frames[len(frames)-1], got[len(got)-1])
		})
	}
}

func TestNativeStreamGuard_MaskInAnInvokeChunk(t *testing.T) {
	t.Parallel()
	chunk := func(inner string) []byte {
		return testEventFrame(t, "chunk", `{"bytes":"`+b64(inner)+`"}`)
	}
	frames := [][]byte{
		chunk(`{"outputText":"Hello there","index":0,"totalOutputTextTokenCount":3,"completionReason":null}`),
		chunk(`{"outputText":" mail ` + streamEmail + ` ok","index":0,"totalOutputTextTokenCount":6,"completionReason":null}`),
		chunk(`{"outputText":" done","index":0,"totalOutputTextTokenCount":8,"completionReason":"FINISH"}`),
	}
	runner := &maskRunner{from: streamEmail, to: "<EMAIL>"}
	got, pe := runNativeGuard(t, nativeGuardFor(runner, streamGuardConfig{headChars: 5, minChars: 1000, maxHold: time.Hour}), frames)
	require.Nil(t, pe)
	require.Len(t, got, 3)
	assert.Equal(t, frames[0], got[0])
	assert.Equal(t, frames[2], got[2])

	msg, err := eventstream.NewDecoder().Decode(bytes.NewReader(got[1]), nil)
	require.NoError(t, err)
	var holder struct {
		Bytes []byte `json:"bytes"`
	}
	require.NoError(t, json.Unmarshal(msg.Payload, &holder))
	assert.Contains(t, string(holder.Bytes), `"outputText":" mail <EMAIL> ok"`)
	assert.Contains(t, string(holder.Bytes), `"totalOutputTextTokenCount":6`, "the family's other fields are kept")
	assert.NotContains(t, string(holder.Bytes), streamEmail)
}

// If the rebuilt window still holds the removed text anywhere, the mask is
// refused and the stream is cut: the leak check is what stands behind the mask.
func TestNativeStreamGuard_LeakInTheWindowFailsOpenAndReleasesTheOriginal(t *testing.T) {
	t.Parallel()
	frames := [][]byte{
		deltaFrame(t, "Hello there"),
		// The email is also in a field the mask never touches.
		testEventFrame(t, "contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":" write to `+streamEmail+`"},"note":"`+streamEmail+`"}`),
		deltaFrame(t, " tail"),
	}
	runner := &maskRunner{from: streamEmail, to: "<EMAIL>"}
	got, pe, rt := runNativeGuardTraced(t, nativeGuardFor(runner, streamGuardConfig{headChars: 5, minChars: 1000, maxHold: time.Hour}), frames)
	require.Nil(t, pe)
	requireStreamFailedOpen(t, got, frames, rt, "leak_remaining")
}

func TestNativeStreamGuard_MaskOfTextAlreadyReleasedFailsOpenAndReleasesTheOriginal(t *testing.T) {
	t.Parallel()
	// The first block is clean and released. The mask then names text inside it.
	frames := [][]byte{
		deltaFrame(t, "Hello "+streamEmail),
		deltaFrame(t, " second block text"),
		deltaFrame(t, " third"),
	}
	released := &lateMaskRunner{from: streamEmail, to: "<EMAIL>"}
	got, pe, rt := runNativeGuardTraced(t, nativeGuardFor(released, streamGuardConfig{headChars: 5, minChars: 1, maxHold: time.Hour}), frames)
	require.Nil(t, pe)
	requireStreamFailedOpen(t, got, frames, rt, "already_released_text")
}

// lateMaskRunner answers the first block clean and masks from the second on.
type lateMaskRunner struct {
	from, to string
	calls    int
}

func (r *lateMaskRunner) RunStreamSegment(_ context.Context, _ appplugins.StageInput, seg appplugins.StreamSegment) (*appplugins.SegmentOutcome, error) {
	if seg.Closing {
		return &appplugins.SegmentOutcome{}, nil
	}
	r.calls++
	if r.calls == 1 {
		return &appplugins.SegmentOutcome{}, nil
	}
	return &appplugins.SegmentOutcome{HasTransform: true, Transformed: strings.ReplaceAll(seg.Accumulated, r.from, r.to)}, nil
}

func TestNativeStreamGuard_MaskInTheHeadBeforeAnythingIsReleased(t *testing.T) {
	t.Parallel()
	frames := [][]byte{deltaFrame(t, "Hello "+streamEmail), deltaFrame(t, " tail")}
	runner := &maskRunner{from: streamEmail, to: "<EMAIL>"}
	got, pe := runNativeGuard(t, nativeGuardFor(runner, streamGuardConfig{headChars: 1000, minChars: 1000, maxHold: time.Hour}), frames)
	require.Nil(t, pe, "a mask in the head is applied, not refused")
	require.Len(t, got, 2)
	assert.NotContains(t, joinedPayloads(t, got), streamEmail)
	assert.Contains(t, decodeFrameText(t, got[0]), "Hello <EMAIL>")
	assert.Equal(t, frames[1], got[1])
}

// A native stream resolves a failed inspection like every other stream: a
// guardrail fails open whatever on_error it still stores, and a passive rewriter
// that asks for fail_closed refuses the stream.
func TestNativeStreamGuard_GuardrailFailureHonoursOnError(t *testing.T) {
	t.Parallel()
	run := func(t *testing.T, planFor func(*testing.T, map[string]any) *appplugins.StagePlan, onError string) (*ForwardResult, [][]byte, *failingSegmentExecutor) {
		frames := textFrames(t, "Hello", " there", " friend")
		settings := map[string]any{"enabled": true, "head_chars": 5}
		if onError != "" {
			settings["on_error"] = onError
		}
		plan := planFor(t, settings)
		exec := &failingSegmentExecutor{err: errors.New("provider down")}
		fwd := &forwarder{executor: exec, codec: adapter.NewRegistry(), logger: newGuardLogger()}
		req := &infracontext.RequestContext{
			SourceFormat:  string(adapter.FormatBedrockNative),
			BedrockNative: &infracontext.BedrockNativeTarget{Op: "converse-stream", ModelID: "m"},
		}
		dto := &forwardRequestDTO{request: req, plan: plan, response: &infracontext.ResponseContext{}}
		res := fwd.finalizeStream(context.Background(), dto,
			&ProviderResponse{StatusCode: 200, Stream: frameSeq(frames), RawFrames: true, StreamView: adapter.BedrockFrameView},
			nil, time.Now())
		return res, frames, exec
	}
	for _, stored := range []string{"", "fail_open", "fail_closed"} {
		t.Run("a guardrail fails open with on_error "+stored, func(t *testing.T) {
			t.Parallel()
			res, frames, exec := run(t, inspectorPlan, stored)
			require.NotNil(t, res.Stream)
			assert.Equal(t, frames, collectFrames(t, res.Stream))
			assert.Positive(t, exec.calls.Load(), "the guard did try to inspect it")
		})
	}
	t.Run("a rewriter that asks for fail_closed refuses the stream before the first byte", func(t *testing.T) {
		t.Parallel()
		res, _, exec := run(t, rewriterPlan, "fail_closed")
		assert.Positive(t, exec.calls.Load())
		assert.Nil(t, res.Stream)
		assert.Equal(t, http.StatusForbidden, res.StatusCode)
	})
}

func TestNativeStreamGuard_NativeStreamsBuildAGuardLikeAnySSEStream(t *testing.T) {
	t.Parallel()
	exec := &countingExecutor{}
	plan := inspectorPlan(t, map[string]any{"enabled": true, "head_chars": 5})
	fwd := &forwarder{executor: exec, codec: adapter.NewRegistry(), logger: newGuardLogger()}
	req := &infracontext.RequestContext{
		SourceFormat:  string(adapter.FormatBedrockNative),
		BedrockNative: &infracontext.BedrockNativeTarget{Op: "converse-stream", ModelID: "m"},
	}
	dto := &forwardRequestDTO{request: req, plan: plan, response: &infracontext.ResponseContext{}}
	frames := textFrames(t, "Hello", " world")

	res := fwd.finalizeStream(context.Background(), dto,
		&ProviderResponse{StatusCode: 200, Stream: frameSeq(frames), RawFrames: true, StreamView: adapter.BedrockFrameView},
		nil, time.Now())
	require.NotNil(t, res.Stream)
	assert.Equal(t, frames, collectFrames(t, res.Stream))
	assert.NotZero(t, exec.segments.Load(), "a native stream is inspected: this is what the old skip prevented")
	assert.True(t, res.Upstream)
	assert.True(t, res.RawFrames)
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// countingExecutor counts the blocks a stream guard hands it, which is the only
// observable proof a guard was built.
type countingExecutor struct {
	plainExecutor
	segments atomic.Int32
}

func (e *countingExecutor) RunStreamSegment(
	context.Context,
	appplugins.StageInput,
	appplugins.StreamSegment,
) (*appplugins.SegmentOutcome, error) {
	e.segments.Add(1)
	return &appplugins.SegmentOutcome{}, nil
}

// failingSegmentExecutor is an executor whose guardrail provider is down.
type failingSegmentExecutor struct {
	plainExecutor
	err   error
	calls atomic.Int32
}

func (e *failingSegmentExecutor) RunStreamSegment(
	_ context.Context,
	_ appplugins.StageInput,
	seg appplugins.StreamSegment,
) (*appplugins.SegmentOutcome, error) {
	if seg.Closing {
		return &appplugins.SegmentOutcome{}, nil
	}
	e.calls.Add(1)
	return nil, e.err
}

// blockOnSecondExecutor clears the head and blocks the next block it is given.
type blockOnSecondExecutor struct {
	plainExecutor
	calls atomic.Int32
}

func (e *blockOnSecondExecutor) RunStreamSegment(
	_ context.Context,
	_ appplugins.StageInput,
	seg appplugins.StreamSegment,
) (*appplugins.SegmentOutcome, error) {
	if seg.Closing {
		return &appplugins.SegmentOutcome{}, nil
	}
	if e.calls.Add(1) >= 2 {
		return &appplugins.SegmentOutcome{Block: true, Type: "guardrail_blocked", Message: "blocked by policy"}, nil
	}
	return &appplugins.SegmentOutcome{}, nil
}

// Through the forwarder the guard must come out native: a cut on the wire is an
// exception frame, not the SSE terminator an OpenAI client would get.
func TestFinalizeStream_NativeBlockEndsOnAnExceptionFrame(t *testing.T) {
	t.Parallel()
	exec := &blockOnSecondExecutor{}
	plan := inspectorPlan(t, map[string]any{"enabled": true, "head_chars": 5})
	fwd := &forwarder{executor: exec, codec: adapter.NewRegistry(), logger: newGuardLogger()}
	req := &infracontext.RequestContext{
		SourceFormat:  string(adapter.FormatBedrockNative),
		BedrockNative: &infracontext.BedrockNativeTarget{Op: "converse-stream", ModelID: "m"},
	}
	dto := &forwardRequestDTO{request: req, plan: plan, response: &infracontext.ResponseContext{}}
	frames := textFrames(t, "Hello", " world", " BAD", " tail")

	res := fwd.finalizeStream(context.Background(), dto,
		&ProviderResponse{StatusCode: 200, Stream: frameSeq(frames), RawFrames: true, StreamView: adapter.BedrockFrameView},
		nil, time.Now())
	require.NotNil(t, res.Stream)
	got := collectFrames(t, res.Stream)
	require.NotEmpty(t, got)
	excType, payload := decodeException(t, got[len(got)-1])
	assert.Equal(t, "validationException", excType)
	assert.Contains(t, payload, "blocked by policy")
	assert.NotContains(t, string(bytes.Join(got, nil)), "data:", "no SSE terminator on an eventstream")
}

// addRunner returns the text with an addition, which is not a mask.
type addRunner struct{}

func (addRunner) RunStreamSegment(_ context.Context, _ appplugins.StageInput, seg appplugins.StreamSegment) (*appplugins.SegmentOutcome, error) {
	if seg.Closing {
		return &appplugins.SegmentOutcome{}, nil
	}
	return &appplugins.SegmentOutcome{HasTransform: true, Transformed: "ADDED " + seg.Accumulated}, nil
}

func TestNativeStreamGuard_AnAdditionIsNotAMaskAndFailsOpen(t *testing.T) {
	t.Parallel()
	frames := [][]byte{deltaFrame(t, "Hello there friend"), deltaFrame(t, " and more")}
	got, pe, rt := runNativeGuardTraced(t, nativeGuardFor(addRunner{}, streamGuardConfig{headChars: 1000, minChars: 1000, maxHold: time.Hour}), frames)
	require.Nil(t, pe)
	requireStreamFailedOpen(t, got, frames, rt, "not_a_text_replacement")
}

// A native stream outlives the lookup the call started, so the model is read again
// when it ends, by the forwarder, on the goroutine that ends the stream and before
// post_response and the metrics event are built.
func TestForwarder_NativeStreamReadsTheModelAtItsEnd(t *testing.T) {
	t.Parallel()
	const appARN = "arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/abc123xyz"
	reg := &registry.Registry{ID: ids.New[ids.RegistryKind]()}
	models := catalogmocks.NewBedrockModelResolver(t)
	models.EXPECT().Lookup(mock.Anything, reg, appARN).Return("anthropic.claude-sonnet-4-5-20250929-v1:0", true).Once()
	f := &forwarder{models: models, logger: newGuardLogger()}
	req := &infracontext.RequestContext{
		SourceFormat:  string(adapter.FormatBedrockNative),
		BedrockNative: &infracontext.BedrockNativeTarget{Op: "converse-stream", ModelID: appARN},
	}
	dto := &forwardRequestDTO{request: req, backend: reg}

	frames := textFrames(t, "Hello")
	rt := trace.New("t", trace.Metadata{})
	got := collectFrames(t, f.refreshModelAtStreamEnd(trace.NewContext(context.Background(), rt), dto, frameSeq(frames)))
	assert.Equal(t, frames, got, "the frames are untouched")
	assert.Equal(t, "anthropic.claude-sonnet-4-5-20250929-v1:0", req.ResolvedModel)

	// A request that is not native, or already resolved, is not looked up.
	plain := &forwardRequestDTO{request: &infracontext.RequestContext{}, backend: reg}
	f.refreshNativeModel(context.Background(), plain)
	assert.Empty(t, plain.request.ResolvedModel)
}

// The model is read again when a native stream ends, through finalizeStream, so the
// request is written on the goroutine that ends the stream and before post_response.
func TestFinalizeStream_NativeReadsTheModelWhenTheStreamEnds(t *testing.T) {
	t.Parallel()
	const appARN = "arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/abc123xyz"
	reg := &registry.Registry{ID: ids.New[ids.RegistryKind]()}
	models := catalogmocks.NewBedrockModelResolver(t)
	models.EXPECT().Lookup(mock.Anything, reg, appARN).Return("anthropic.claude-sonnet-4-5-20250929-v1:0", true).Once()
	fwd := &forwarder{executor: &failingSegmentExecutor{}, codec: adapter.NewRegistry(), logger: newGuardLogger(), models: models}
	req := &infracontext.RequestContext{
		SourceFormat:  string(adapter.FormatBedrockNative),
		BedrockNative: &infracontext.BedrockNativeTarget{Op: "converse-stream", ModelID: appARN},
	}
	dto := &forwardRequestDTO{request: req, backend: reg, plan: inspectorPlan(t, map[string]any{"enabled": true, "head_chars": 5}), response: &infracontext.ResponseContext{}}
	frames := textFrames(t, "Hello", " there")

	res := fwd.finalizeStream(context.Background(), dto,
		&ProviderResponse{StatusCode: 200, Stream: frameSeq(frames), RawFrames: true, StreamView: adapter.BedrockFrameView},
		nil, time.Now())
	require.NotNil(t, res.Stream)
	assert.Empty(t, req.ResolvedModel, "not known before the stream ends")
	assert.Equal(t, frames, collectFrames(t, res.Stream))
	assert.Equal(t, "anthropic.claude-sonnet-4-5-20250929-v1:0", req.ResolvedModel)
}
