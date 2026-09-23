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
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdaptStream_BedrockClientGetsOneMergedMetadataAfterMessageStop(t *testing.T) {
	upstream := linesSeq(
		`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","usage":{"input_tokens":10,"output_tokens":1,"cache_read_input_tokens":1000,"cache_creation_input_tokens":300,"cache_creation":{"ephemeral_5m_input_tokens":100,"ephemeral_1h_input_tokens":200}}}}`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}`,
		`data: {"type":"content_block_stop","index":0}`,
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}`,
		`data: {"type":"message_stop"}`,
	)

	lines := collectLines(t, adaptStream(upstream, adapter.NewRegistry(), adapter.FormatBedrock, adapter.FormatAnthropic, slog.Default(), nil))

	var events []adapter.ConverseStreamEvent
	for _, line := range lines {
		payload, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		var ev adapter.ConverseStreamEvent
		require.NoError(t, json.Unmarshal([]byte(payload), &ev))
		events = append(events, ev)
	}
	require.NotEmpty(t, events)

	var metadata []*adapter.ConverseMetadata
	for _, ev := range events {
		if ev.Metadata != nil {
			metadata = append(metadata, ev.Metadata)
		}
	}
	require.Len(t, metadata, 1, "exactly one metadata event")
	last := events[len(events)-1]
	require.NotNil(t, last.Metadata, "metadata closes the stream")
	require.NotNil(t, events[len(events)-2].MessageStop, "metadata follows messageStop")

	assert.Equal(t, &adapter.ConverseUsage{
		InputTokens: 10, OutputTokens: 7, TotalTokens: 1317,
		CacheReadInputTokens: 1000, CacheWriteInputTokens: 300,
		CacheDetails: []adapter.ConverseCacheDetail{{InputTokens: 200, TTL: "1h"}, {InputTokens: 100, TTL: "5m"}},
	}, last.Metadata.Usage)
}

func TestAdaptStream_BedrockClientWithoutUsageEmitsNoMetadata(t *testing.T) {
	upstream := linesSeq(
		`data: {"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"}}]}`,
		`data: {"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
		`data: [DONE]`,
	)

	lines := collectLines(t, adaptStream(upstream, adapter.NewRegistry(), adapter.FormatBedrock, adapter.FormatOpenAI, slog.Default(), nil))

	joined := strings.Join(lines, "\n")
	assert.Contains(t, joined, `"messageStop"`)
	assert.NotContains(t, joined, `"metadata"`)
}
