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
	"log/slog"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
)

func TestFinishDeferralIgnoresEmptyTerminalAfterFlush(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	deferred := &finishDeferral{target: adapter.FormatAnthropic, flushed: true}
	terminal := &adapter.CanonicalStreamChunk{StreamEnd: true}
	assert.True(t, deferred.dropAfterFlush(terminal, adapter.FormatGemini, logger))
	assert.Empty(t, logs.String())
	assert.False(t, deferred.dropLogged)

	content := &adapter.CanonicalStreamChunk{Delta: "late content"}
	assert.True(t, deferred.dropAfterFlush(content, adapter.FormatGemini, logger))
	assert.True(t, deferred.dropAfterFlush(content, adapter.FormatGemini, logger))
	assert.Equal(t, 1, strings.Count(logs.String(), "stream chunk after the flushed finish dropped"))
}

func TestFinishDeferralWarnsForNonemptyTerminalAfterFlush(t *testing.T) {
	for _, chunk := range []*adapter.CanonicalStreamChunk{
		{StreamEnd: true, Role: "assistant"},
		{StreamEnd: true, Delta: "late content"},
		{StreamEnd: true, ReasoningDelta: "late reasoning"},
		{StreamEnd: true, ToolCallDeltas: []adapter.StreamToolCallDelta{{Name: "late_tool"}}},
		{StreamEnd: true, Usage: &adapter.CanonicalUsage{OutputTokens: 1}},
		{StreamEnd: true, FinishReason: "stop"},
	} {
		var logs bytes.Buffer
		deferred := &finishDeferral{target: adapter.FormatAnthropic, flushed: true}
		assert.True(t, deferred.dropAfterFlush(chunk, adapter.FormatGemini, slog.New(slog.NewTextHandler(&logs, nil))))
		assert.Contains(t, logs.String(), "stream chunk after the flushed finish dropped")
	}
}
