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

package metrics

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const (
	maxPreviewRunes   = 200
	previewEllipsis   = "…"
	mcpToolCallMethod = "tools/call"
)

// promptPreview is the start of the last user turn: in a multi-turn request
// it is the message this request adds, which is what the Activity list names.
// JSON in the turn gets the body's credential redaction before it is cut,
// while it still parses.
func promptPreview(canonical *adapter.CanonicalRequest) string {
	if canonical == nil {
		return ""
	}
	for i := len(canonical.Messages) - 1; i >= 0; i-- {
		msg := canonical.Messages[i]
		if msg.Role != "user" {
			continue
		}
		if text := truncatePreview(events.RedactCredentialsInText(msg.Content, maxPreviewRunes)); text != "" {
			return text
		}
	}
	return ""
}

// toolCallPreview reads the sanitized JSON-RPC body, so a credential the
// client put in the arguments is already redacted; its key is skipped too,
// and JSON pasted among the argument's prose is redacted like a prompt.
func toolCallPreview(mcp *events.MCP, body string) string {
	if mcp == nil || mcp.Method != mcpToolCallMethod || mcp.Tool == "" {
		return ""
	}
	tool := truncatePreview(mcp.Tool)
	budget := maxPreviewRunes - utf8.RuneCountInString(tool) - len("()")
	arg := truncateRunes(events.RedactCredentialsInText(firstStringArgument(body), budget), budget)
	if arg == "" {
		return tool
	}
	return tool + "(" + arg + ")"
}

// firstStringArgument walks params.arguments as a token stream because a Go
// map would lose the order the client wrote the arguments in, and the first
// one is the closest thing to a tool's main argument.
func firstStringArgument(body string) string {
	var envelope struct {
		Params struct {
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		return ""
	}
	dec := json.NewDecoder(bytes.NewReader(envelope.Params.Arguments))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return ""
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return ""
		}
		key, _ := keyTok.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return ""
		}
		if events.IsCredentialKey(key) {
			continue
		}
		var text string
		if json.Unmarshal(value, &text) != nil || strings.TrimSpace(text) == "" {
			continue
		}
		return text
	}
	return ""
}

func truncatePreview(text string) string {
	return truncateRunes(text, maxPreviewRunes)
}

func truncateRunes(text string, limit int) string {
	collapsed := strings.Join(strings.Fields(text), " ")
	if utf8.RuneCountInString(collapsed) <= limit {
		return collapsed
	}
	if limit <= 0 {
		return ""
	}
	runes := []rune(collapsed)
	return strings.TrimSpace(string(runes[:limit])) + previewEllipsis
}
