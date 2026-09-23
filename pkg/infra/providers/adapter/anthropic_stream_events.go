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

package adapter

// AnthropicStopReasonUnmapped reports whether finishReason has no Anthropic
// stop_reason and so reaches an Anthropic client as a plain end_turn, as
// Gemini's OTHER and LANGUAGE do.
func AnthropicStopReasonUnmapped(finishReason string) bool {
	switch finishReason {
	case "", "stop", "end_turn":
		return false
	default:
		return anthropicStopReason(finishReason) == "end_turn"
	}
}

// anthropicStopReason maps a canonical finish reason to an Anthropic
// stop_reason. Gemini block reasons reach the canonical model verbatim.
func anthropicStopReason(finishReason string) string {
	switch finishReason {
	case "length":
		return "max_tokens"
	case "tool_calls":
		return "tool_use"
	case "stop_sequence":
		return "stop_sequence"
	case "model_context_window_exceeded":
		return "model_context_window_exceeded"
	case "content_filter", "refusal", "SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST", "SPII", "RECITATION", "IMAGE_SAFETY":
		return "refusal"
	default:
		return "end_turn"
	}
}
