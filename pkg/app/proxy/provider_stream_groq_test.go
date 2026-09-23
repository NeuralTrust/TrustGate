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
	"encoding/json"
	"iter"
	"testing"

	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	providermocks "github.com/NeuralTrust/TrustGate/pkg/infra/providers/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const groqFinishWithUsage = `data: {"id":"chatcmpl-groq","object":"chat.completion.chunk","model":"openai/gpt-oss-120b","choices":[{"index":0,"delta":{},"finish_reason":"length"}],` +
	`"x_groq":{"usage":{"prompt_tokens":1678,"completion_tokens":32,"total_tokens":1710,"prompt_tokens_details":{"cached_tokens":1536},"completion_tokens_details":{"reasoning_tokens":30}}},` +
	`"usage":{"prompt_tokens":1678,"completion_tokens":32,"total_tokens":1710,"prompt_tokens_details":{"cached_tokens":1536},"completion_tokens_details":{"reasoning_tokens":30}}}`

func TestInvokeStream_GroqRequestsIncludeUsageAndRecordsCachedUsage(t *testing.T) {
	tests := []struct {
		name         string
		sourceFormat string
		body         string
	}{
		{name: "openai client", body: openaiRequestBody},
		{name: "anthropic client", sourceFormat: "anthropic", body: anthropicRequestBody},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var sent []byte
			client := providermocks.NewClient(t)
			client.EXPECT().
				CompletionsStream(mock.Anything, mock.Anything, mock.Anything).
				RunAndReturn(func(_ context.Context, _ *providers.Config, body []byte) (iter.Seq2[[]byte, error], error) {
					sent = body
					return seqOf([]byte(groqFinishWithUsage), []byte("data: [DONE]")), nil
				}).
				Once()
			inv := newStreamInvoker(t, "groq", client)
			req := &infracontext.RequestContext{Body: []byte(tc.body), SourceFormat: tc.sourceFormat}
			rt := trace.New("trace-groq", trace.Metadata{})
			require.NotNil(t, rt.StartSpan(trace.SpanLLM, "groq"))
			ctx := trace.NewContext(context.Background(), rt)

			resp, err := inv.InvokeStream(ctx, apiKeyTarget("groq"), req)
			require.NoError(t, err)
			collectStream(t, resp.Stream)

			var got struct {
				Stream        bool `json:"stream"`
				StreamOptions struct {
					IncludeUsage bool `json:"include_usage"`
				} `json:"stream_options"`
			}
			require.NoError(t, json.Unmarshal(sent, &got))
			assert.True(t, got.Stream)
			assert.True(t, got.StreamOptions.IncludeUsage, "Groq upstream must be asked for the include_usage chunk")

			usage := rt.LLMUsage()
			require.NotNil(t, usage)
			assert.Equal(t, 1678, usage.InputTokens)
			assert.Equal(t, 32, usage.OutputTokens)
			assert.Equal(t, 1710, usage.TotalTokens)
			assert.Equal(t, 1536, usage.CachedInputTokens)
			assert.Equal(t, 30, usage.ReasoningOutputTokens)
		})
	}
}
