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
	"iter"
	"strings"
	"testing"

	appproxy "github.com/NeuralTrust/AgentGateway/pkg/app/proxy"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	factorymocks "github.com/NeuralTrust/AgentGateway/pkg/infra/providers/factory/mocks"
	providermocks "github.com/NeuralTrust/AgentGateway/pkg/infra/providers/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const geminiRequestBody = `{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`

func seqOf(lines ...[]byte) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		for _, l := range lines {
			if !yield(l, nil) {
				return
			}
		}
	}
}

func collectStream(t *testing.T, s iter.Seq2[[]byte, error]) []string {
	t.Helper()
	require.NotNil(t, s, "expected a non-nil stream")
	var out []string
	for line, err := range s {
		require.NoError(t, err)
		out = append(out, string(line))
	}
	return out
}

func newStreamInvoker(t *testing.T, provider string, client *providermocks.Client) appproxy.ProviderInvoker {
	t.Helper()
	locator := factorymocks.NewProviderLocator(t)
	locator.EXPECT().Get(provider).Return(client, nil).Once()
	return appproxy.NewProviderInvoker(locator, adapter.NewRegistry(), newTestLogger())
}

func TestInvokeStream_PassthroughStream(t *testing.T) {
	lines := [][]byte{
		[]byte(`data: {"choices":[{"index":0,"delta":{"content":"hi"}}]}`),
		{},
		[]byte("data: [DONE]"),
	}
	client := providermocks.NewClient(t)
	client.EXPECT().
		CompletionsStream(mock.Anything, mock.Anything, mock.Anything).
		Return(seqOf(lines...), nil).
		Once()

	inv := newStreamInvoker(t, "openai", client)
	req := &infracontext.RequestContext{Context: context.Background(), Body: []byte(openaiRequestBody)}

	resp, err := inv.InvokeStream(context.Background(), apiKeyTarget("openai"), req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, []string{"text/event-stream"}, resp.Headers["Content-Type"])
	assert.Equal(t, []string{"openai"}, resp.Headers["X-Selected-Provider"])

	got := collectStream(t, resp.Stream)
	assert.Equal(t, []string{
		`data: {"choices":[{"index":0,"delta":{"content":"hi"}}]}`,
		``,
		`data: [DONE]`,
	}, got)
}

func TestInvokeStream_CrossFormatAdapt(t *testing.T) {
	// Registry (anthropic) emits an anthropic content delta; the client speaks
	// openai, so adaptStream converts anthropic -> openai.
	anthropicChunk := []byte(`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}`)
	client := providermocks.NewClient(t)
	client.EXPECT().
		CompletionsStream(mock.Anything, mock.Anything, mock.Anything).
		Return(seqOf(anthropicChunk), nil).
		Once()

	inv := newStreamInvoker(t, "anthropic", client)
	req := &infracontext.RequestContext{Context: context.Background(), Body: []byte(openaiRequestBody)}

	resp, err := inv.InvokeStream(context.Background(), apiKeyTarget("anthropic"), req)
	require.NoError(t, err)
	assert.Equal(t, "openai", req.SourceFormat)
	assert.Equal(t, "anthropic", req.TargetFormat)

	joined := strings.Join(collectStream(t, resp.Stream), "\n")
	assert.Contains(t, joined, "chat.completion.chunk")
	assert.Contains(t, joined, "Hello")
}

func TestInvokeStream_GeminiToolCallAccumulation(t *testing.T) {
	// Source gemini, backend openai with incremental tool_calls. adaptStream
	// accumulates the deltas and flushes them as a Gemini functionCall on finish.
	chunks := [][]byte{
		[]byte(`data: {"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}`),
		[]byte(`data: {"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":\"SF\"}"}}]}}]}`),
		[]byte(`data: {"object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`),
	}
	client := providermocks.NewClient(t)
	client.EXPECT().
		CompletionsStream(mock.Anything, mock.Anything, mock.Anything).
		Return(seqOf(chunks...), nil).
		Once()

	inv := newStreamInvoker(t, "openai", client)
	req := &infracontext.RequestContext{
		Context:      context.Background(),
		Body:         []byte(geminiRequestBody),
		SourceFormat: "google",
	}

	resp, err := inv.InvokeStream(context.Background(), apiKeyTarget("openai"), req)
	require.NoError(t, err)

	joined := strings.Join(collectStream(t, resp.Stream), "\n")
	assert.Contains(t, joined, "functionCall")
	assert.Contains(t, joined, "get_weather")
}

func TestInvokeStream_PreStreamBackendErrorPassthrough(t *testing.T) {
	errBody := []byte(`{"error":{"message":"rate limited"}}`)
	client := providermocks.NewClient(t)
	client.EXPECT().
		CompletionsStream(mock.Anything, mock.Anything, mock.Anything).
		Return(nil, registrydomain.NewBackendError(429, errBody)).
		Once()

	inv := newStreamInvoker(t, "openai", client)
	req := &infracontext.RequestContext{Context: context.Background(), Body: []byte(openaiRequestBody)}

	resp, err := inv.InvokeStream(context.Background(), apiKeyTarget("openai"), req)
	require.NoError(t, err)
	assert.Nil(t, resp.Stream, "pre-stream error must not open a stream")
	assert.Equal(t, 429, resp.StatusCode)
	assert.Equal(t, errBody, resp.Body)
}

func TestInvokeStream_UsageObserverRecordsFinalUsage(t *testing.T) {
	lines := [][]byte{
		[]byte(`data: {"id":"chatcmpl-stream","choices":[{"index":0,"delta":{"content":"hi"}}]}`),
		[]byte(`data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`),
		[]byte("data: [DONE]"),
	}
	client := providermocks.NewClient(t)
	client.EXPECT().
		CompletionsStream(mock.Anything, mock.Anything, mock.Anything).
		Return(seqOf(lines...), nil).
		Once()

	inv := newStreamInvoker(t, "openai", client)
	req := &infracontext.RequestContext{Context: context.Background(), Body: []byte(openaiRequestBody)}

	rt := trace.New("trace-1", trace.Metadata{})
	span := rt.StartSpan(trace.SpanLLM, "openai")
	ctx := trace.NewContext(context.Background(), rt)

	resp, err := inv.InvokeStream(ctx, apiKeyTarget("openai"), req)
	require.NoError(t, err)

	_ = collectStream(t, resp.Stream)

	usage := rt.LLMUsage()
	require.NotNil(t, usage, "expected streamed usage to land on the LLM span")
	assert.Equal(t, 10, usage.InputTokens)
	assert.Equal(t, 5, usage.OutputTokens)
	assert.Equal(t, 15, usage.TotalTokens)

	attrs, ok := span.LLMAttrsCopy()
	require.True(t, ok)
	assert.Equal(t, "chatcmpl-stream", attrs.TurnID, "streamed provider id captured as turn id")
}
