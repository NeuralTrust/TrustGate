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
	// mcpCallThroughTool is appmcp.CallToolName, which this package cannot
	// import (app/mcp imports it). Its arguments wrap the called tool's own.
	mcpCallThroughTool = "trustgate_call_tool"
	// mcpCallAgentTool is appmcp.CallAgentToolName. Its span names the agent,
	// and its preview is the message sent to it.
	mcpCallAgentTool = "trustgate_call_agent"
	// mcpGatewayCallTool is appmcp.GatewayCallToolName, which calls either a
	// tool (its arguments wrap the tool's own, as the call-through's do) or an
	// agent (its preview is the message, as for mcpCallAgentTool).
	mcpGatewayCallTool = "trustgate_call"
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
	if message, ok := callAgentMessage(body); ok {
		if message == "" {
			return tool
		}
		return truncatePreview(events.RedactCredentialsInText(message, maxPreviewRunes))
	}
	budget := maxPreviewRunes - utf8.RuneCountInString(tool) - len("()")
	arg := truncateRunes(events.RedactCredentialsInText(firstStringArgument(body), budget), budget)
	if arg == "" {
		return tool
	}
	return tool + "(" + arg + ")"
}

// a2aMessagePreview is the text an A2A call sends: the text parts of
// params.message, as A2A 0.3 ({"kind":"text","text":…}) and 1.0 ({"text":…})
// write them. A call with no message (GetTask, CancelTask) has none. The body
// is the sanitized one, and the text gets a prompt's credential redaction.
func a2aMessagePreview(body string) string {
	var envelope struct {
		Method string `json:"method"`
		Params struct {
			ID      string `json:"id"`
			Message struct {
				Parts []struct {
					Kind string `json:"kind"`
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"message"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		return ""
	}
	if len(envelope.Params.Message.Parts) == 0 {
		if preview := chatBridgePreview(body); preview != "" {
			return preview
		}
		// A call that carries no message (tasks/get, GetTask…) is named by its
		// method and the task it names.
		return truncatePreview(strings.TrimSpace(envelope.Method + " " + envelope.Params.ID))
	}
	texts := make([]string, 0, len(envelope.Params.Message.Parts))
	for _, part := range envelope.Params.Message.Parts {
		if part.Text != "" && (part.Kind == "" || part.Kind == "text") {
			texts = append(texts, part.Text)
		}
	}
	return truncatePreview(events.RedactCredentialsInText(strings.Join(texts, " "), maxPreviewRunes))
}

// chatBridgePreview is the last user message of an OpenAI chat completions
// request, which the agent plane's bridge sends to the agent.
func chatBridgePreview(body string) string {
	var chat struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if json.Unmarshal([]byte(body), &chat) != nil {
		return ""
	}
	for i := len(chat.Messages) - 1; i >= 0; i-- {
		if chat.Messages[i].Role != "user" {
			continue
		}
		var text string
		if json.Unmarshal(chat.Messages[i].Content, &text) != nil {
			var parts []struct {
				Text string `json:"text"`
			}
			_ = json.Unmarshal(chat.Messages[i].Content, &parts)
			texts := make([]string, 0, len(parts))
			for _, p := range parts {
				texts = append(texts, p.Text)
			}
			text = strings.Join(texts, " ")
		}
		return truncatePreview(events.RedactCredentialsInText(text, maxPreviewRunes))
	}
	return ""
}

// callAgentMessage is the message of a call to an agent through the Store,
// empty for a task read. ok is false for any other call.
func callAgentMessage(body string) (message string, ok bool) {
	var envelope struct {
		Params struct {
			Name      string `json:"name"`
			Arguments struct {
				Agent   string `json:"agent"`
				Message string `json:"message"`
			} `json:"arguments"`
		} `json:"params"`
	}
	if json.Unmarshal([]byte(body), &envelope) != nil {
		return "", false
	}
	switch envelope.Params.Name {
	case mcpCallAgentTool:
		return strings.TrimSpace(envelope.Params.Arguments.Message), true
	case mcpGatewayCallTool:
		if strings.TrimSpace(envelope.Params.Arguments.Agent) == "" {
			return "", false
		}
		return strings.TrimSpace(envelope.Params.Arguments.Message), true
	default:
		return "", false
	}
}

// firstStringArgument walks params.arguments as a token stream because a Go
// map would lose the order the client wrote the arguments in, and the first
// one is the closest thing to a tool's main argument.
func firstStringArgument(body string) string {
	var envelope struct {
		Params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		return ""
	}
	arguments := envelope.Params.Arguments
	if envelope.Params.Name == mcpCallThroughTool || envelope.Params.Name == mcpGatewayCallTool {
		// The span names the tool the call-through called, so the preview
		// reads that tool's arguments, not the wrapper's (whose first string
		// is the tool's own name).
		var wrapped struct {
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(arguments, &wrapped); err != nil {
			return ""
		}
		arguments = wrapped.Arguments
	}
	dec := json.NewDecoder(bytes.NewReader(arguments))
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
