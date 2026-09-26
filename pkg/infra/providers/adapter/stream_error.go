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

import (
	"bytes"
	"encoding/json"
)

// UpstreamStreamError is the error object an upstream sent as a stream
// payload, as OpenAI-wire providers do when they fail after the response has
// started. A decoder reports it on CanonicalStreamChunk.UpstreamError.
type UpstreamStreamError struct {
	Type    string
	Code    string
	Message string
}

func (e *UpstreamStreamError) Error() string {
	if e.Message == "" {
		return "upstream sent a stream error: code " + e.Code
	}
	return "upstream sent a stream error: " + e.Message
}

// UpstreamErrorOnly reports whether c carries an upstream error and nothing
// else, the chunk a decoder returns for an error payload with no content,
// finish or usage.
func (c *CanonicalStreamChunk) UpstreamErrorOnly() bool {
	return c.UpstreamError != nil &&
		c.ID == "" && c.Model == "" && c.Role == "" && c.Delta == "" &&
		c.ReasoningDelta == "" && c.FinishReason == "" &&
		len(c.ToolCallDeltas) == 0 && c.Usage == nil && len(c.ProviderExtensions) == 0
}

type streamErrorBody struct {
	Type    string          `json:"type"`
	Code    json.RawMessage `json:"code"`
	Message string          `json:"message"`
}

// decodeStreamError returns the upstream error carried by raw, the value of a
// payload's top-level "error" key, or nil when raw is absent or carries no
// error: null, false, 0, an empty string, or an object with neither a message
// nor a code.
func decodeStreamError(raw json.RawMessage) *UpstreamStreamError {
	raw = bytes.TrimSpace(raw)
	switch string(raw) {
	case "", "null", "false", "0", `""`:
		return nil
	}
	var message string
	if json.Unmarshal(raw, &message) == nil {
		if message == "" {
			return nil
		}
		return &UpstreamStreamError{Message: message}
	}
	var body streamErrorBody
	if json.Unmarshal(raw, &body) != nil {
		return &UpstreamStreamError{Message: string(raw)}
	}
	code := string(bytes.Trim(body.Code, `"`))
	switch code {
	case "null", "0", "false":
		code = ""
	}
	if body.Message == "" && code == "" {
		return nil
	}
	return &UpstreamStreamError{Type: body.Type, Code: code, Message: body.Message}
}

// FinishFailure returns a client-facing message when finishReason reports that
// the upstream failed to produce a usable message rather than completing one:
// OpenRouter's "error" and Gemini's function call failures.
func FinishFailure(finishReason string) (string, bool) {
	switch finishReason {
	case "error":
		return "upstream reported an error while generating the message", true
	case "MALFORMED_FUNCTION_CALL":
		return "upstream generated a malformed tool call", true
	case "UNEXPECTED_TOOL_CALL":
		return "upstream called a tool that was not declared", true
	case "TOO_MANY_TOOL_CALLS":
		return "upstream made too many tool calls", true
	default:
		return "", false
	}
}
