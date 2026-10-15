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
	"log/slog"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
)

func TestAdaptStream_ChatClientOfResponsesRequiresValidTerminal(t *testing.T) {
	for _, source := range []adapter.Format{adapter.FormatOpenAI, adapter.FormatAzure} {
		for _, tc := range []struct {
			name     string
			terminal []string
			success  bool
		}{
			{name: "completed without usage", terminal: []string{`data: {"type":"response.completed","response":{"id":"resp_1","model":"model_1","usage":null}}`}, success: true},
			{name: "EOF"},
			{name: "invalid completion", terminal: []string{`data: {"type":"response.completed","response":42}`}},
			{name: "error", terminal: []string{`data: {"type":"error","message":"private upstream detail"}`}},
			{name: "malformed before completion", terminal: []string{`data: {invalid`, `data: {"type":"response.completed","response":{}}`}},
		} {
			t.Run(string(source)+"/"+tc.name, func(t *testing.T) {
				upstream := append([]string{
					`data: {"type":"response.created","response":{"id":"resp_1","model":"model_1"}}`,
					`data: {"type":"response.output_text.delta","delta":"hello"}`,
				}, tc.terminal...)
				stream := adaptStream(linesSeq(upstream...), adapter.NewRegistry(), source, adapter.FormatOpenAIResponses, slog.Default(), nil, withStreamIncludeUsage(true))
				var lines []string
				var streamErr error
				for line, err := range stream {
					if err != nil {
						streamErr = err
					} else {
						lines = append(lines, string(line))
					}
				}
				joined := strings.Join(lines, "\n")
				assert.Contains(t, joined, `"id":"resp_1"`)
				assert.Contains(t, joined, `"model":"model_1"`)
				assert.NotContains(t, joined, "private upstream detail")
				if tc.success {
					assert.NoError(t, streamErr)
					assert.Equal(t, 1, strings.Count(joined, "[DONE]"))
					assert.Equal(t, 1, strings.Count(joined, `"finish_reason":"stop"`))
				} else {
					assert.Error(t, streamErr)
					assert.Contains(t, joined, `"error"`)
					assert.NotContains(t, joined, "[DONE]")
					assert.NotContains(t, joined, `"finish_reason"`)
				}
			})
		}
	}
}
