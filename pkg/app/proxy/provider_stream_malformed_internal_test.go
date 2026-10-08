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

func TestAdaptStream_MalformedKnownEventSkippedForNonChatClients(t *testing.T) {
	upstreams := []struct {
		target adapter.Format
		lines  []string
	}{
		{adapter.FormatAnthropic, []string{
			`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","usage":{"input_tokens":3,"output_tokens":1}}}`,
			`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
			`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}`,
			`data: {"type":"content_block_delta","index":0,"delta":42}`,
			`data: {"type":"content_block_stop","index":0}`,
			`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}`,
			`data: {"type":"message_stop"}`,
		}},
		{adapter.FormatGemini, []string{
			`data: {"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]}}]}`,
			`data: {"candidates":[{"content":{"parts":[{"text":42}]}}]}`,
			`data: {"candidates":[{"content":{"role":"model","parts":[{"text":""}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":2,"totalTokenCount":3}}`,
		}},
	}
	terminals := map[adapter.Format]string{
		adapter.FormatAnthropic:       `"type":"message_stop"`,
		adapter.FormatOpenAIResponses: `"type":"response.completed"`,
		adapter.FormatCohere:          `"type":"message-end"`,
		adapter.FormatGemini:          `"finishReason":"STOP"`,
	}
	for _, upstream := range upstreams {
		for source, terminal := range terminals {
			if source == upstream.target {
				continue
			}
			t.Run(string(source)+"<-"+string(upstream.target), func(t *testing.T) {
				lines, err := collectLinesAndError(adaptStream(linesSeq(upstream.lines...), adapter.NewRegistry(),
					source, upstream.target, slog.New(slog.DiscardHandler), nil))
				assert.NoError(t, err)
				joined := strings.Join(lines, "\n")
				assert.Contains(t, joined, terminal)
				assert.Contains(t, joined, "hi")
			})
		}
	}
}
