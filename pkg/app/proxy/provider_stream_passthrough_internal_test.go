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
	"errors"
	"io"
	"iter"
	"log/slog"
	"strings"
	"syscall"
	"testing"
	"testing/iotest"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A same-format client gets the upstream's lines verbatim, so whether its
// answer is whole depends on the upstream reaching the event its wire format
// ends a response with. These tests pin that a stream ending before it ends
// with an error the transport turns into an error event, and that one ending
// on it, or on an error the upstream sent itself, does not get a second one.

const (
	passthroughOpenAIChunk  = `data: {"id":"c","object":"chat.completion.chunk","model":"gpt","choices":[{"index":0,"delta":{"role":"assistant","content":"hal"}}]}`
	passthroughOpenAIFinish = `data: {"id":"c","object":"chat.completion.chunk","model":"gpt","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`
	passthroughOpenAIError  = `data: {"error":{"message":"The server had an error","type":"server_error"}}`
)

func passthroughAnthropicHead() []string {
	return []string{
		"event: message_start",
		`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","content":[],"usage":{"input_tokens":3,"output_tokens":1}}}`,
		"",
		"event: content_block_start",
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		"",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hal"}}`,
		"",
	}
}

func passthroughAnthropicTail() []string {
	return []string{
		"event: content_block_stop",
		`data: {"type":"content_block_stop","index":0}`,
		"",
		"event: message_delta",
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}`,
		"",
		"event: message_stop",
		`data: {"type":"message_stop"}`,
		"",
	}
}

// failAfter yields lines and then err, as a provider stream whose read failed.
func failAfter(err error, lines ...string) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		for _, l := range lines {
			if !yield([]byte(l), nil) {
				return
			}
		}
		yield(nil, err)
	}
}

func passthrough(upstream iter.Seq2[[]byte, error], format adapter.Format) iter.Seq2[[]byte, error] {
	return adaptStream(upstream, adapter.NewRegistry(), format, format, slog.New(slog.DiscardHandler), nil)
}

func TestAdaptStream_OpenAIPassthroughWithoutDoneEndsWithAnError(t *testing.T) {
	upstream := []string{passthroughOpenAIChunk, "", passthroughOpenAIFinish, ""}
	var logs bytes.Buffer
	stream := adaptStream(linesSeq(upstream...), adapter.NewRegistry(), adapter.FormatOpenAI, adapter.FormatOpenAI,
		slog.New(slog.NewTextHandler(&logs, nil)), nil)

	lines, err := collectLinesAndError(stream)

	require.ErrorIs(t, err, errPassthroughUnterminated)
	_, notified := errors.AsType[*ClientNotifiedStreamError](err)
	assert.False(t, notified, "the client has been told nothing, so the transport must write the error event")
	assert.Equal(t, upstream, lines, "every upstream line still reaches the client verbatim")
	assert.Contains(t, logs.String(), "upstream stream ended before its terminal event")
}

// A finish_reason is not where a Chat Completions stream ends: the
// include_usage chunk follows it, and [DONE] follows that.
func TestAdaptStream_OpenAIPassthroughWithDoneEndsCleanly(t *testing.T) {
	upstream := []string{passthroughOpenAIChunk, "", passthroughOpenAIFinish, "", "data: [DONE]", ""}

	lines, err := collectLinesAndError(passthrough(linesSeq(upstream...), adapter.FormatOpenAI))

	require.NoError(t, err)
	assert.Equal(t, upstream, lines)
}

func TestAdaptStream_OpenAIWireFamiliesPassthroughWithoutDoneEndWithAnError(t *testing.T) {
	upstream := []string{passthroughOpenAIChunk, "", passthroughOpenAIFinish, ""}
	for _, format := range []adapter.Format{adapter.FormatAzure, adapter.FormatGroq, adapter.FormatMistral, adapter.FormatOpenRouter} {
		_, err := collectLinesAndError(passthrough(linesSeq(upstream...), format))
		assert.ErrorIs(t, err, errPassthroughUnterminated, "%s", format)

		_, err = collectLinesAndError(passthrough(linesSeq(append(upstream, "data: [DONE]", "")...), format))
		assert.NoError(t, err, "%s", format)
	}
}

func TestAdaptStream_AnthropicPassthroughWithoutMessageStopEndsWithAnError(t *testing.T) {
	upstream := passthroughAnthropicHead()

	lines, err := collectLinesAndError(passthrough(linesSeq(upstream...), adapter.FormatAnthropic))

	require.ErrorIs(t, err, errPassthroughUnterminated)
	assert.Equal(t, upstream, lines)
}

// message_delta carries the stop reason, but message_stop is the event the
// Anthropic SDKs end a message on.
func TestAdaptStream_AnthropicPassthroughCutAfterMessageDeltaEndsWithAnError(t *testing.T) {
	upstream := append(passthroughAnthropicHead(), passthroughAnthropicTail()[:6]...)

	_, err := collectLinesAndError(passthrough(linesSeq(upstream...), adapter.FormatAnthropic))

	require.ErrorIs(t, err, errPassthroughUnterminated)
}

func TestAdaptStream_AnthropicPassthroughWithMessageStopEndsCleanly(t *testing.T) {
	upstream := append(passthroughAnthropicHead(), passthroughAnthropicTail()...)

	lines, err := collectLinesAndError(passthrough(linesSeq(upstream...), adapter.FormatAnthropic))

	require.NoError(t, err)
	assert.Equal(t, upstream, lines)
}

// The client already read the upstream's own error event; a second one from
// the gateway would report the same failure twice.
func TestAdaptStream_PassthroughUpstreamErrorIsNotReportedTwice(t *testing.T) {
	anthropic := append(passthroughAnthropicHead(),
		"event: error",
		`data: {"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`,
		"",
	)
	_, err := collectLinesAndError(passthrough(linesSeq(anthropic...), adapter.FormatAnthropic))
	assert.NoError(t, err, "anthropic")

	openai := []string{passthroughOpenAIChunk, "", passthroughOpenAIError, ""}
	_, err = collectLinesAndError(passthrough(linesSeq(openai...), adapter.FormatOpenAI))
	assert.NoError(t, err, "openai")

	gemini := []string{`data: {"error":{"code":500,"message":"Internal error","status":"INTERNAL"}}`, ""}
	_, err = collectLinesAndError(passthrough(linesSeq(gemini...), adapter.FormatGemini))
	assert.NoError(t, err, "gemini")

	responses := []string{
		"event: response.failed",
		`data: {"type":"response.failed","response":{"id":"resp_1","model":"gpt-5","status":"failed"}}`,
		"",
	}
	_, err = collectLinesAndError(passthrough(linesSeq(responses...), adapter.FormatOpenAIResponses))
	assert.NoError(t, err, "responses")
}

// An event the decoder cannot read is not an error the upstream sent, so it
// does not stand in for the terminal.
func TestAdaptStream_PassthroughUnreadableEventDoesNotEndTheStream(t *testing.T) {
	upstream := append(passthroughAnthropicHead(), `data: {"type":"message_delta","delta":"not an object"}`, "")

	_, err := collectLinesAndError(passthrough(linesSeq(upstream...), adapter.FormatAnthropic))

	require.ErrorIs(t, err, errPassthroughUnterminated)
}

// A read that fails before the terminal is a truncated answer, and reaches the
// transport as itself, which writes the error event.
func TestAdaptStream_PassthroughResetBeforeTheTerminalIsAPlainError(t *testing.T) {
	reset := errors.New("read tcp: connection reset by peer")

	lines, err := collectLinesAndError(passthrough(failAfter(reset, passthroughAnthropicHead()...), adapter.FormatAnthropic))

	require.ErrorIs(t, err, reset)
	_, notified := errors.AsType[*ClientNotifiedStreamError](err)
	assert.False(t, notified)
	assert.Equal(t, passthroughAnthropicHead(), lines)
}

// A read that fails after message_stop cost the client nothing: an error
// event behind a finished message would tell it the message failed.
func TestAdaptStream_PassthroughResetAfterTheTerminalIsClientNotified(t *testing.T) {
	reset := errors.New("read tcp: connection reset by peer")
	upstream := append(passthroughAnthropicHead(), passthroughAnthropicTail()...)

	lines, err := collectLinesAndError(passthrough(failAfter(reset, upstream...), adapter.FormatAnthropic))

	notified, ok := errors.AsType[*ClientNotifiedStreamError](err)
	require.True(t, ok, "got %v", err)
	assert.ErrorIs(t, notified, reset)
	assert.Equal(t, upstream, lines)
}

// Gemini sends no [DONE] and no closing event: the candidate's finishReason on
// the last chunk is its end.
func TestAdaptStream_GeminiPassthroughEndsOnTheFinishReason(t *testing.T) {
	text := `data: {"candidates":[{"content":{"role":"model","parts":[{"text":"hal"}]},"index":0}],"modelVersion":"gemini-2.5-flash","responseId":"r1"}`
	finish := `data: {"candidates":[{"content":{"role":"model","parts":[{"text":"f"}]},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":3,"candidatesTokenCount":2,"totalTokenCount":5},"modelVersion":"gemini-2.5-flash","responseId":"r1"}`

	_, err := collectLinesAndError(passthrough(linesSeq(text, ""), adapter.FormatGemini))
	assert.ErrorIs(t, err, errPassthroughUnterminated, "gemini without a finish")

	_, err = collectLinesAndError(passthrough(linesSeq(text, "", finish, ""), adapter.FormatGemini))
	assert.NoError(t, err, "gemini with a finish")

	_, err = collectLinesAndError(passthrough(linesSeq(text, ""), adapter.FormatVertex))
	assert.ErrorIs(t, err, errPassthroughUnterminated, "vertex without a finish")

	_, err = collectLinesAndError(passthrough(linesSeq(text, "", finish, ""), adapter.FormatVertex))
	assert.NoError(t, err, "vertex with a finish")
}

func TestAdaptStream_ResponsesPassthroughEndsOnItsClosingEvent(t *testing.T) {
	head := []string{
		"event: response.created",
		`data: {"type":"response.created","response":{"id":"resp_1","model":"gpt-5"}}`,
		"",
		"event: response.output_text.delta",
		`data: {"type":"response.output_text.delta","output_index":0,"delta":"hal"}`,
		"",
	}
	completed := []string{
		"event: response.completed",
		`data: {"type":"response.completed","response":{"id":"resp_1","model":"gpt-5"}}`,
		"",
	}
	incomplete := []string{
		"event: response.incomplete",
		`data: {"type":"response.incomplete","response":{"id":"resp_1","model":"gpt-5","incomplete_details":{"reason":"max_output_tokens"}}}`,
		"",
	}

	_, err := collectLinesAndError(passthrough(linesSeq(head...), adapter.FormatOpenAIResponses))
	assert.ErrorIs(t, err, errPassthroughUnterminated)

	_, err = collectLinesAndError(passthrough(linesSeq(append(head, completed...)...), adapter.FormatOpenAIResponses))
	assert.NoError(t, err, "response.completed")

	_, err = collectLinesAndError(passthrough(linesSeq(append(head, incomplete...)...), adapter.FormatOpenAIResponses))
	assert.NoError(t, err, "response.incomplete")
}

func TestAdaptStream_CoherePassthroughEndsOnMessageEnd(t *testing.T) {
	upstream := strings.Split(cohereUpstreamToolCallStream, "\n")
	end := -1
	for i, line := range upstream {
		if line == "event: message-end" {
			end = i
		}
	}
	require.Positive(t, end)

	_, err := collectLinesAndError(passthrough(linesSeq(upstream[:end]...), adapter.FormatCohere))
	assert.ErrorIs(t, err, errPassthroughUnterminated, "cut before message-end")

	_, err = collectLinesAndError(passthrough(linesSeq(upstream[:end+3]...), adapter.FormatCohere))
	assert.NoError(t, err, "message-end without [DONE]")
}

// Bedrock Converse events do not come through StreamSSE, and the gateway does
// not hold them to a terminal.
func TestAdaptStream_BedrockPassthroughIsNotHeldToATerminal(t *testing.T) {
	upstream := []string{`data: {"messageStart":{"role":"assistant"}}`, ""}

	lines, err := collectLinesAndError(passthrough(linesSeq(upstream...), adapter.FormatBedrock))

	require.NoError(t, err)
	assert.Equal(t, upstream, lines)
}

// Over the real reader: the [DONE] event reaches a same-format client whole,
// with one blank line after it, whether or not the upstream sent its own.
func TestAdaptStream_OpenAIPassthroughOverStreamSSEEndsWithTheWholeDoneEvent(t *testing.T) {
	for _, body := range []string{
		passthroughOpenAIChunk + "\n\ndata: [DONE]\n\n",
		passthroughOpenAIChunk + "\n\ndata: [DONE]\n",
		passthroughOpenAIChunk + "\n\ndata: [DONE]",
	} {
		upstream := providers.StreamSSE(context.Background(), io.NopCloser(strings.NewReader(body)))

		lines := collectLines(t, passthrough(upstream, adapter.FormatOpenAI))

		assert.Equal(t, passthroughOpenAIChunk+"\n\ndata: [DONE]\n\n", strings.Join(lines, "\n")+"\n", "%q", body)
	}
}

func TestAdaptStream_OpenAIPassthroughOverStreamSSEResetIsAnError(t *testing.T) {
	body := io.MultiReader(strings.NewReader(passthroughOpenAIChunk+"\n\n"), iotest.ErrReader(syscall.ECONNRESET))
	upstream := providers.StreamSSE(context.Background(), io.NopCloser(body))

	lines, err := collectLinesAndError(passthrough(upstream, adapter.FormatOpenAI))

	require.ErrorIs(t, err, syscall.ECONNRESET)
	_, notified := errors.AsType[*ClientNotifiedStreamError](err)
	assert.False(t, notified)
	assert.Equal(t, []string{passthroughOpenAIChunk, ""}, lines)
}

func TestAdaptStream_OpenAIPassthroughOverStreamSSECleanCloseBeforeDoneIsAnError(t *testing.T) {
	body := io.NopCloser(strings.NewReader(passthroughOpenAIChunk + "\n\n" + passthroughOpenAIFinish + "\n\n"))

	_, err := collectLinesAndError(passthrough(providers.StreamSSE(context.Background(), body), adapter.FormatOpenAI))

	require.ErrorIs(t, err, errPassthroughUnterminated)
}

// The usage observer still sees every chunk of a passthrough, decoded once for
// it and for the terminal.
func TestAdaptStream_PassthroughStillReportsChunksToTheObserver(t *testing.T) {
	usage := `data: {"id":"c","object":"chat.completion.chunk","model":"gpt","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`
	upstream := []string{passthroughOpenAIChunk, "", passthroughOpenAIFinish, "", usage, "", "data: [DONE]", ""}
	var observed []*adapter.CanonicalStreamChunk

	lines := collectLines(t, adaptStream(linesSeq(upstream...), adapter.NewRegistry(), adapter.FormatOpenAI, adapter.FormatOpenAI,
		slog.New(slog.DiscardHandler), func(c *adapter.CanonicalStreamChunk) { observed = append(observed, c) }))

	assert.Equal(t, upstream, lines)
	require.Len(t, observed, 3)
	assert.Equal(t, "stop", observed[1].FinishReason)
	require.NotNil(t, observed[2].Usage)
	assert.Equal(t, 2, observed[2].Usage.OutputTokens)
}

// The stream guard wraps the same sequence: the error a passthrough ends with
// has to come out of it as the error it went in as.
func TestStreamGuard_PassthroughWithoutTerminalStillEndsWithItsError(t *testing.T) {
	runner := &scriptedRunner{}
	g := newStreamGuard(runner, adapter.NewRegistry(), adapter.FormatOpenAI, stageInputFixture(),
		streamGuardConfig{}, newGuardLogger())
	upstream := []string{passthroughOpenAIChunk, "", passthroughOpenAIFinish, ""}

	out, pe := g.Run(context.Background(), passthrough(linesSeq(upstream...), adapter.FormatOpenAI))

	require.Nil(t, pe)
	got, err := collectGuardOutput(t, g, out)
	require.ErrorIs(t, err, errPassthroughUnterminated)
	_, notified := errors.AsType[*ClientNotifiedStreamError](err)
	assert.False(t, notified)
	assert.Equal(t, upstream, got)
}

func TestStreamGuard_PassthroughResetAfterTheTerminalStaysClientNotified(t *testing.T) {
	runner := &scriptedRunner{}
	g := newStreamGuard(runner, adapter.NewRegistry(), adapter.FormatAnthropic, stageInputFixture(),
		streamGuardConfig{}, newGuardLogger())
	reset := errors.New("read tcp: connection reset by peer")
	upstream := append(passthroughAnthropicHead(), passthroughAnthropicTail()...)

	out, pe := g.Run(context.Background(), passthrough(failAfter(reset, upstream...), adapter.FormatAnthropic))

	require.Nil(t, pe)
	got, err := collectGuardOutput(t, g, out)
	notified, ok := errors.AsType[*ClientNotifiedStreamError](err)
	require.True(t, ok, "got %v", err)
	assert.ErrorIs(t, notified, reset)
	assert.Equal(t, upstream, got)
}
