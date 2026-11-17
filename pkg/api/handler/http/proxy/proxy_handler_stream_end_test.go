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

package proxy_test

import (
	"context"
	"io"
	"iter"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"syscall"
	"testing"
	"testing/iotest"

	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	factorymocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory/mocks"
	providermocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// These tests drive a same-format stream from the upstream body to the client
// body: the provider reader, the passthrough and the handler, with only the
// forwarder between the last two mocked out. What the client receives is the
// whole point, so it is compared byte for byte.

const (
	streamEndChunk       = `data: {"id":"c","object":"chat.completion.chunk","model":"gpt","choices":[{"index":0,"delta":{"role":"assistant","content":"hal"}}]}`
	streamEndFinish      = `data: {"id":"c","object":"chat.completion.chunk","model":"gpt","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`
	streamEndOpenAIError = `data: {"error":{"message":"upstream stream terminated unexpectedly","type":"upstream_error"}}`
)

// upstreamStream returns the client stream InvokeStream builds for provider
// over an upstream whose response body is body.
func upstreamStream(t *testing.T, provider string, source adapter.Format, requestBody string, body io.Reader) iter.Seq2[[]byte, error] {
	t.Helper()
	client := providermocks.NewClient(t)
	client.EXPECT().
		CompletionsStream(mock.Anything, mock.Anything, mock.Anything).
		RunAndReturn(func(ctx context.Context, _ *providers.Config, _ []byte) (iter.Seq2[[]byte, error], error) {
			return providers.StreamResponse(ctx, io.NopCloser(body)), nil
		}).
		Once()
	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get(provider).Return(client, nil).Once()
	invoker := appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), slog.New(slog.DiscardHandler))
	target := &registrydomain.Registry{
		ID:   ids.New[ids.RegistryKind](),
		Name: provider,
		LLMTarget: &registrydomain.LLMTarget{
			Provider: provider,
			Auth:     registrydomain.NewAPIKeyAuth("secret"),
		},
	}
	req := &infracontext.RequestContext{Body: []byte(requestBody), SourceFormat: string(source)}

	resp, err := invoker.InvokeStream(context.Background(), target, req)
	require.NoError(t, err)
	require.NotNil(t, resp.Stream)
	return resp.Stream
}

func openAIUpstreamStream(t *testing.T, body io.Reader) iter.Seq2[[]byte, error] {
	t.Helper()
	return upstreamStream(t, "openai", adapter.FormatOpenAI,
		`{"model":"gpt","messages":[{"role":"user","content":"hi"}]}`, body)
}

func relayToClient(t *testing.T, req *http.Request, stream iter.Seq2[[]byte, error]) string {
	t.Helper()
	app, fwd := newTestApp(t)
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(&appproxy.ForwardResult{
			StatusCode: http.StatusOK,
			Headers:    map[string][]string{"Content-Type": {"text/event-stream"}},
			Stream:     stream,
		}, nil).
		Once()

	resp, err := app.Test(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

// The [DONE] event reaches a same-format client whole: the data line and the
// blank line that dispatches it, once. It used to arrive as "data: [DONE]\n",
// an event a strict SSE parser drops (customer findings F04/T04).
func TestHandle_Streaming_PassthroughEndsWithTheWholeDoneEvent(t *testing.T) {
	upstream := streamEndChunk + "\n\n" + streamEndFinish + "\n\ndata: [DONE]\n\n"

	got := relayToClient(t, newProxyRequest(), openAIUpstreamStream(t, strings.NewReader(upstream)))

	assert.Equal(t, upstream, got)
}

// An upstream that sends [DONE] without its blank line still leaves the client
// with a whole event, and one that sends it does not leave two.
func TestHandle_Streaming_PassthroughDoneSeparatorIsWrittenOnce(t *testing.T) {
	want := streamEndChunk + "\n\ndata: [DONE]\n\n"

	assert.Equal(t, want, relayToClient(t, newProxyRequest(),
		openAIUpstreamStream(t, strings.NewReader(streamEndChunk+"\n\ndata: [DONE]"))))
	assert.Equal(t, want, relayToClient(t, newProxyRequest(),
		openAIUpstreamStream(t, strings.NewReader(streamEndChunk+"\n\ndata: [DONE]\n\n\n\n"))))
}

// A reset partway through used to end the client stream as if it had finished
// (customer finding T02). The client now gets the stream error event.
func TestHandle_Streaming_PassthroughResetEndsWithTheErrorEvent(t *testing.T) {
	body := io.MultiReader(strings.NewReader(streamEndChunk+"\n\n"), iotest.ErrReader(syscall.ECONNRESET))

	got := relayToClient(t, newProxyRequest(), openAIUpstreamStream(t, body))

	assert.Equal(t, streamEndChunk+"\n\n"+streamEndOpenAIError+"\n\n", got)
}

// An upstream that closes its body cleanly before [DONE] has not finished
// either, whatever the transport says.
func TestHandle_Streaming_PassthroughCleanCloseBeforeDoneEndsWithTheErrorEvent(t *testing.T) {
	upstream := streamEndChunk + "\n\n" + streamEndFinish + "\n\n"

	got := relayToClient(t, newProxyRequest(), openAIUpstreamStream(t, strings.NewReader(upstream)))

	assert.Equal(t, upstream+streamEndOpenAIError+"\n\n", got)
}

// A reset between an event's lines leaves the client inside that event. The
// error event has to start an event of its own, or the Anthropic SDK reads one
// "error" event whose data is two payloads run together.
func TestHandle_Streaming_AnthropicPassthroughResetMidEventEndsWithItsOwnErrorEvent(t *testing.T) {
	const head = "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","content":[],"usage":{"input_tokens":3,"output_tokens":1}}}` + "\n\n" +
		"event: content_block_start\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n" +
		"event: content_block_delta\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hal"}}` + "\n"
	body := io.MultiReader(strings.NewReader(head), iotest.ErrReader(syscall.ECONNRESET))
	stream := upstreamStream(t, "anthropic", adapter.FormatAnthropic,
		`{"model":"claude","max_tokens":10,"stream":true,"messages":[{"role":"user","content":"hi"}]}`, body)
	req := httptest.NewRequest(http.MethodPost, "/"+consumerSlug+"/v1/messages", strings.NewReader(`{"model":"claude","max_tokens":8}`))
	req.Header.Set("Content-Type", "application/json")

	got := relayToClient(t, req, stream)

	assert.Equal(t, head+"\n"+
		"event: error\n"+
		`data: {"type":"error","error":{"type":"api_error","message":"upstream stream terminated unexpectedly"}}`+"\n\n\n", got)
}

// After message_stop the client has its whole message, so a reset on the way
// to the end of the body adds nothing to what it reads.
func TestHandle_Streaming_AnthropicPassthroughResetAfterMessageStopAddsNoErrorEvent(t *testing.T) {
	const upstream = "event: message_start\n" +
		`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","content":[],"usage":{"input_tokens":3,"output_tokens":1}}}` + "\n\n" +
		"event: message_delta\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}` + "\n\n" +
		"event: message_stop\n" +
		`data: {"type":"message_stop"}` + "\n\n"
	body := io.MultiReader(strings.NewReader(upstream), iotest.ErrReader(syscall.ECONNRESET))
	stream := upstreamStream(t, "anthropic", adapter.FormatAnthropic,
		`{"model":"claude","max_tokens":10,"stream":true,"messages":[{"role":"user","content":"hi"}]}`, body)
	req := httptest.NewRequest(http.MethodPost, "/"+consumerSlug+"/v1/messages", strings.NewReader(`{"model":"claude","max_tokens":8}`))
	req.Header.Set("Content-Type", "application/json")

	got := relayToClient(t, req, stream)

	assert.Equal(t, upstream, got)
}
