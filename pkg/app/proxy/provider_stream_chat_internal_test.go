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
	"errors"
	"io"
	"iter"
	"log/slog"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func chatSequence(payloads ...string) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		for _, payload := range payloads {
			if !yield([]byte(payload), nil) {
				return
			}
		}
	}
}

func TestChatResponsesRequiresActualResponseTerminal(t *testing.T) {
	start := `data: {"type":"response.created","response":{"id":"resp_chat","model":"actual-model"}}`
	text := `data: {"type":"response.output_text.delta","delta":"hello"}`
	complete := `data: {"type":"response.completed","response":{"id":"resp_chat","model":"actual-model","usage":{"input_tokens":3,"output_tokens":2,"total_tokens":5}}}`
	for _, tc := range []struct {
		name     string
		payloads []string
		failed   bool
	}{
		{"complete", []string{start, text, complete}, false},
		{"complete_without_usage", []string{start, text, `data: {"type":"response.completed","response":{"id":"resp_chat","model":"actual-model"}}`}, false},
		{"early_eof", []string{start, text}, true},
		{"tool_done_is_not_terminal", []string{start, `data: {"type":"response.function_call_arguments.done","arguments":"{}"}`}, true},
		{"error", []string{start, text, `data: {"type":"error","message":"private detail"}`, complete}, true},
		{"malformed", []string{start, `data: {invalid`, complete}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var frames []string
			var failure error
			for line, err := range adaptChatStream(chatSequence(tc.payloads...), adapter.NewRegistry(), adapter.FormatOpenAIResponses, nil, chatStreamOptions{includeUsage: true, model: "chosen-model"}) {
				if err != nil {
					failure = err
				} else {
					frames = append(frames, string(line))
				}
			}
			joined := strings.Join(frames, "\n")
			if tc.failed {
				require.Error(t, failure)
				var notified *ClientNotifiedStreamError
				assert.True(t, errors.As(failure, &notified))
				assert.NotContains(t, joined, "[DONE]")
				assert.NotContains(t, joined, `"finish_reason"`)
				assert.NotContains(t, joined, `"usage"`)
				assert.NotContains(t, joined, "private detail")
			} else {
				require.NoError(t, failure)
				assert.Equal(t, 1, strings.Count(joined, "[DONE]"))
				assert.Contains(t, joined, `"id":"resp_chat"`)
				assert.Contains(t, joined, `"model":"actual-model"`)
				assert.Contains(t, joined, "hello")
			}
		})
	}
}

func TestChatBackportPreservesMainMistralAndNonChatPaths(t *testing.T) {
	registry := adapter.NewRegistry()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, tc := range []struct {
		name           string
		source, target adapter.Format
		payloads       []string
	}{
		{"mistral_upstream", adapter.FormatOpenAI, adapter.FormatMistral, []string{`data: {"id":"chat","choices":[{"delta":{"content":"hello"}}]}`, `data: [DONE]`}},
		{"non_chat_client", adapter.FormatAnthropic, adapter.FormatOpenAI, []string{`data: {"id":"chat","choices":[{"delta":{"content":"hello"}}]}`}},
		{"same_wire", adapter.FormatOpenAI, adapter.FormatOpenRouter, []string{`data: {"choices":[{"delta":{"content":"hello"}}]}`, `data: [DONE]`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var frames []string
			for line, err := range adaptStream(chatSequence(tc.payloads...), registry, tc.source, tc.target, logger, nil) {
				require.NoError(t, err)
				frames = append(frames, string(line))
			}
			joined := strings.Join(frames, "\n")
			assert.Contains(t, joined, "hello")
			assert.NotContains(t, joined, `"error"`)
			if tc.name != "non_chat_client" {
				assert.Equal(t, 1, strings.Count(joined, "[DONE]"))
			}
		})
	}
}

func TestAdaptedOpenAIWireErrorsDoNotFinishSuccessfully(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, source := range []adapter.Format{adapter.FormatOpenAI, adapter.FormatAzure, adapter.FormatAnthropic} {
		for _, target := range []adapter.Format{adapter.FormatOpenRouter, adapter.FormatGroq} {
			t.Run(string(source)+"/"+string(target), func(t *testing.T) {
				for _, failed := range []string{
					`data: {"error":{"type":"invalid_stream_event","code":"provider_failure","message":"actual provider error"}}`,
					`data: {"choices":[{"delta":{},"finish_reason":"error"}]}`,
				} {
					var frames []string
					var failure error
					seq := chatSequence(`data: {"choices":[{"delta":{"content":"hello"}}]}`, failed, `data: [DONE]`)
					for line, err := range adaptStream(seq, adapter.NewRegistry(), source, target, logger, nil) {
						if err != nil {
							failure = err
						} else {
							frames = append(frames, string(line))
						}
					}
					require.Error(t, failure)
					assert.NotContains(t, strings.Join(frames, "\n"), "[DONE]")
					assert.NotContains(t, strings.Join(frames, "\n"), `"finish_reason"`)
				}
			})
		}
	}
}
