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

package trustguard

import (
	"encoding/json"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// maxBufferedTextBytes is the most text a buffered leg sends in one evaluate
// call. It counts what a model would read, unescaped: the system prompt,
// message contents, the arguments of tool calls and the tool definitions.
// Attachments, JSON escaping and the envelope do not count, so an image or a
// long agent session is not refused for being heavy. The largest production
// context windows are about a million tokens, roughly 4 MiB of English; 8 MiB
// is twice that and still under the 10 MiB body limit TrustGuard enforces
// itself, which a text of this size therefore never reaches. Above it the
// request is the input's doing and is refused locally as payload_too_large,
// instead of running the call into its timeout, which fails open. TrustGuard
// echoes the payload back on a transform, so splitting it across calls cannot
// give one rewritten body; this ceiling is the alternative.
const maxBufferedTextBytes = 8 << 20

// requestTextBytes is the unescaped text of a decoded LLM request.
func requestTextBytes(creq *adapter.CanonicalRequest) int {
	if creq == nil {
		return 0
	}
	n := len(creq.System)
	for _, msg := range creq.Messages {
		n += len(msg.Content)
		for _, call := range msg.ToolCalls {
			n += len(call.Arguments)
		}
	}
	return n + toolsTextBytes(creq.Tools)
}

// responseTextBytes is the unescaped text of a decoded LLM response and of the
// request's tool definitions the output leg forwards with it.
func responseTextBytes(cresp *adapter.CanonicalResponse, tools []adapter.CanonicalTool) int {
	n := toolsTextBytes(tools)
	if cresp == nil {
		return n
	}
	n += len(cresp.Content)
	if cresp.Reasoning != nil {
		n += len(cresp.Reasoning.ThinkingText)
	}
	for _, call := range cresp.ToolCalls {
		n += len(call.Arguments)
	}
	return n
}

func toolsTextBytes(tools []adapter.CanonicalTool) int {
	n := 0
	for _, tool := range tools {
		n += len(tool.Name) + len(strings.TrimSpace(tool.Description))
		if tool.Schema != nil {
			if raw, err := json.Marshal(tool.Schema); err == nil {
				n += len(raw)
			}
		}
	}
	return n
}

// mcpOutputTextBytes is the unescaped text of an MCP result: its text blocks
// and string leaves, or, for a tools/list answer that has none, the metadata of
// the listed tools.
func mcpOutputTextBytes(body []byte) int {
	if n := len(mcpOutputText(body)); n > 0 {
		return n
	}
	return len(body)
}
