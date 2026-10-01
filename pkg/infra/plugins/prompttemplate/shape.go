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
		if veto := rb.vetoNonCanonical(false, "messages", "system"); veto != nil {
			return veto
		}
		return rb.vetoOpaqueMessages()
	}
	if format == adapter.FormatVertex && adapter.IsSameWireFormat(format, adapter.FormatGemini) {
		format = adapter.FormatGemini
	}
	switch {
	case adapter.IsSameWireFormat(format, adapter.FormatOpenAI), format == adapter.FormatMistral:
		// These adapters decode a body with input and no messages as a
		// Responses request (OpenAIAdapter.DecodeRequest; Mistral and OpenRouter
		// delegate to it), so that is how it is edited here too.
		if rb.isResponsesShaped() {
			rb.shape, rb.format = shapeResponses, adapter.FormatOpenAI
			return rb.vetoResponses(adapter.FormatOpenAI, body)
		}
		rb.format = format
		if veto := rb.vetoNonCanonical(false, "messages", "system"); veto != nil {
			return veto
		}
		return rb.vetoOpaqueMessages()
	case format == adapter.FormatCohere:
		rb.format = format
		if veto := rb.vetoNonCanonical(false, "messages", "system"); veto != nil {
			return veto
		}
		return rb.vetoOpaqueMessages()
	case format == adapter.FormatAnthropic:
		rb.shape, rb.format = shapeAnthropic, format
		if veto := rb.vetoNonCanonical(false, "messages", "system"); veto != nil {
			return veto
		}
		return rb.vetoOpaqueMessages()
	case format == adapter.FormatGemini:
		rb.shape, rb.format = shapeGemini, format
		if adapter.HasAmbiguousKeys(adapter.FormatGemini, body) {
			return &passThrough{decision: decisionSkippedShape, reason: "ambiguous_gemini_keys"}
		}
		// The adapter reads both spellings of systemInstruction and ignores
		// underscores in the fold (adapter.geminiKey).
		if veto := rb.vetoNonCanonical(true, "contents", "systemInstruction", "system_instruction"); veto != nil {
			return veto
		}
		if raw, ok := rb.fields[rb.systemInstructionKey()]; ok && !isJSONNull(raw) {
			var obj map[string]json.RawMessage
			if json.Unmarshal(raw, &obj) != nil || obj == nil {
				return &passThrough{decision: decisionSkippedShape, reason: reasonSystemInstructionBad}
			}
		}
		if raw, ok := rb.fields["contents"]; ok && !isJSONNull(raw) {
			var contents []json.RawMessage
			if err := json.Unmarshal(raw, &contents); err != nil {
				return &passThrough{decision: decisionSkippedShape, reason: reasonContentsNotArray}
			}
		}
		return nil
	case format == adapter.FormatOpenAIResponses:
		rb.shape, rb.format = shapeResponses, format
		return rb.vetoResponses(format, body)
	case format == adapter.FormatBedrock:
		rb.shape, rb.format = shapeBedrock, format
		if adapter.HasAmbiguousKeys(format, body) {
			return &passThrough{decision: decisionSkippedShape, reason: "ambiguous_bedrock_keys"}
		}
		if veto := rb.vetoNonCanonical(false, "messages", "system"); veto != nil {
			return veto
		}
		return rb.vetoOpaqueMessages()
	default:
		return &passThrough{decision: decisionSkippedFormat, reason: "unsupported_format:" + string(format)}
	}
}

func (rb *requestBody) vetoResponses(f adapter.Format, body []byte) *passThrough {
	if adapter.HasAmbiguousKeys(f, body) {
		return &passThrough{decision: decisionSkippedShape, reason: "ambiguous_responses_keys"}
	}
	if veto := rb.vetoNonCanonical(false, "input", "instructions"); veto != nil {
		return veto
	}
	if raw, ok := rb.fields["input"]; ok && !isJSONNull(raw) {
		if _, ok := rb.responsesInput(); !ok {
			return &passThrough{decision: decisionSkippedShape, reason: reasonInputUnreadable}
		}
	}
	return nil
}

// vetoNonCanonical refuses a body with a top-level key that the adapter would
// match to a field this plugin reads or writes but that is not spelled exactly
// like it. encoding/json matches struct fields with Unicode simple folding, so
// "Messages" and "inſtructions" (U+017F) both decode into the field; editing
// the canonical spelling next to one would leave two keys, and after marshal
// the client's copy can win and silently drop the injection. strings.EqualFold
// uses the same folding. exact lists the spellings that are fine as they are;
// with ignoreUnderscores the fold also drops "_", as adapter.geminiKey does.
func (rb *requestBody) vetoNonCanonical(ignoreUnderscores bool, exact ...string) *passThrough {
	fold := func(s string) string {
		if ignoreUnderscores {
			return strings.ReplaceAll(s, "_", "")
		}
		return s
	}
	for k := range rb.fields {
		if slicesContains(exact, k) {
			continue
		}
		for _, c := range exact {
			if strings.EqualFold(fold(k), fold(c)) {
				return &passThrough{decision: decisionSkippedShape, reason: "non_canonical_key"}
			}
		}
	}
	return nil
}

func slicesContains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// isResponsesShaped reports a body the OpenAI chat adapter decodes as a
// Responses request: it mirrors adapter.isResponsesAPIRequest (unexported),
// input present and messages absent. An explicit "messages": null is still a
// chat body there.
func (rb *requestBody) isResponsesShaped() bool {
	if _, ok := rb.fields["input"]; !ok {
		return false
	}
	_, hasMessages := rb.fields["messages"]
	return !hasMessages
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
