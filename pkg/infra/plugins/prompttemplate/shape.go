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

package prompttemplate

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

var templateRefToken = []byte("{template://")

// passThrough describes a request the plugin leaves untouched.
type passThrough struct {
	decision string
	reason   string
}

// applyFormat picks the body shape from the request's wire format. The plugin
// models system+messages (OpenAI family, Cohere, Mistral), Anthropic Messages and native
// Gemini. A format it does not model, or a body it cannot edit without
// guessing, is returned as a passThrough: editing it as OpenAI created a
// stray messages array the upstream ignored while the event reported success.
//
// A request whose format cannot be resolved keeps the historical
// system+messages behaviour.
func (rb *requestBody) applyFormat(provider, sourceFormat string, mcp bool, body []byte) *passThrough {
	format, err := adapter.ResolveAgentFormat(provider, sourceFormat, nil)
	if err != nil {
		if mcp {
			// An MCP tools/call carries no provider and no source format, and its
			// body is a JSON-RPC params object, not a conversation: guessing the
			// system+messages shape there would inject into nothing.
			return &passThrough{decision: decisionSkippedFormat, reason: "unresolved_format"}
		}
		return rb.vetoOpaqueMessages()
	}
	if format == adapter.FormatVertex && adapter.IsSameWireFormat(format, adapter.FormatGemini) {
		format = adapter.FormatGemini
	}
	switch {
	case adapter.IsSameWireFormat(format, adapter.FormatOpenAI), format == adapter.FormatCohere, format == adapter.FormatMistral:
		if rb.isResponsesShaped() {
			return &passThrough{decision: decisionSkippedShape, reason: "responses_shaped_body"}
		}
		return rb.vetoOpaqueMessages()
	case format == adapter.FormatAnthropic:
		rb.shape = shapeAnthropic
		return rb.vetoOpaqueMessages()
	case format == adapter.FormatGemini:
		rb.shape = shapeGemini
		if adapter.HasAmbiguousKeys(adapter.FormatGemini, body) {
			return &passThrough{decision: decisionSkippedShape, reason: "ambiguous_gemini_keys"}
		}
		if hasNonCanonicalGeminiKey(rb.fields) {
			return &passThrough{decision: decisionSkippedShape, reason: "non_canonical_gemini_key"}
		}
		if raw, ok := rb.fields["contents"]; ok && !isJSONNull(raw) {
			var contents []json.RawMessage
			if err := json.Unmarshal(raw, &contents); err != nil {
				return &passThrough{decision: decisionSkippedShape, reason: reasonContentsNotArray}
			}
		}
		return nil
	default:
		return &passThrough{decision: decisionSkippedFormat, reason: "unsupported_format:" + string(format)}
	}
}

// hasNonCanonicalGeminiKey reports a top-level key the adapter reads as
// contents or systemInstruction (it folds keys as adapter.geminiKey does: case
// insensitive, underscores ignored) that this plugin would not find, such as
// "Contents" or "SYSTEM_INSTRUCTION". Editing the canonical spelling next to
// it would leave two fields the upstream may read in either order.
func hasNonCanonicalGeminiKey(fields map[string]json.RawMessage) bool {
	for k := range fields {
		switch k {
		case "contents", "systemInstruction", "system_instruction":
			continue
		}
		switch strings.ToLower(strings.ReplaceAll(k, "_", "")) {
		case "contents", "systeminstruction":
			return true
		}
	}
	return false
}

// isResponsesShaped reports an OpenAI Responses API body that arrived under a
// chat format: it has input and no messages. It mirrors the criterion of
// adapter.isResponsesAPIRequest (unexported), except that an explicit
// "messages": null also counts as absent.
func (rb *requestBody) isResponsesShaped() bool {
	if _, ok := rb.fields["input"]; !ok {
		return false
	}
	raw, ok := rb.fields["messages"]
	return !ok || isJSONNull(raw)
}

func (rb *requestBody) vetoOpaqueMessages() *passThrough {
	if rb.messagesOpaque {
		return &passThrough{decision: decisionSkippedShape, reason: reasonMessagesNotArray}
	}
	return nil
}

func hasTemplateReference(body []byte) bool {
	return bytes.Contains(body, templateRefToken)
}
