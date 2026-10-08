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
	"errors"
	"reflect"
	"slices"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// transformTarget carries the closure that applies TrustGuard's masked text back
// into the provider body for the current direction. apply is nil when the path
// (e.g. native MCP) cannot propagate a rewritten body.
type transformTarget struct {
	isResponse bool
	apply      func(masked string) ([]byte, bool)
	// applyPayload rebuilds the body from the structured payload TrustGuard
	// echoes back: the masked JSON-RPC envelope for protocol=mcp, the masked
	// messages[] for an LLM request. Either way there is nothing to re-split:
	// the masked values are lifted straight out of it by position. Tried before
	// apply, which stays as the fallback for a string-shaped payload.
	applyPayload func(payload map[string]any) ([]byte, bool)
}

// transformedInput extracts the masked string TrustGuard returns for rewrite.
// Prefer the legacy "input" key (response path and older clients). For LLM
// request evaluates that send messages[], fall back to joining non-empty
// message contents in the same order as requestParts.
func transformedInput(payload map[string]any) (string, bool) {
	if payload == nil {
		return "", false
	}
	if value, ok := payload[transformedInputKey]; ok {
		masked, ok := value.(string)
		return masked, ok
	}
	return joinedTransformedMessages(payload)
}

// requestParts returns the ordered text segments TrustGate sends to TrustGuard:
// the system prompt (when non-empty) followed by each non-empty message content.
// joinRequestText and applyMaskedRequest must build this list identically so the
// masked result maps back to the exact segments that were inspected.
func requestParts(creq *adapter.CanonicalRequest) []string {
	parts := make([]string, 0, len(creq.Messages)+1)
	if strings.TrimSpace(creq.System) != "" {
		parts = append(parts, creq.System)
	}
	for _, msg := range creq.Messages {
		if strings.TrimSpace(msg.Content) != "" {
			parts = append(parts, msg.Content)
		}
	}
	return parts
}

func joinRequestText(creq *adapter.CanonicalRequest) string {
	return strings.Join(requestParts(creq), "\n")
}

// rewriteRequest re-encodes the request in full once the mask changes its
// text: an in-place edit could leave a copy of the masked text in a field the
// canonical request does not model, so a redaction never keeps those fields.
// An unchanged text forwards original as it came.
func rewriteRequest(reg *adapter.Registry, format adapter.Format, original []byte, creq *adapter.CanonicalRequest, masked string) ([]byte, bool) {
	return rewriteRequestWith(reg, format, original, creq, func(creq *adapter.CanonicalRequest) bool {
		return applyMaskedRequest(creq, masked)
	})
}

// rewriteRequestFromMessages is rewriteRequest for the messages[] payload
// TrustGuard echoes on a protocol=llm transform: each masked message is mapped
// back by position rather than re-split out of joined text.
func rewriteRequestFromMessages(reg *adapter.Registry, format adapter.Format, original []byte, creq *adapter.CanonicalRequest, payload map[string]any) ([]byte, bool) {
	return rewriteRequestWith(reg, format, original, creq, func(creq *adapter.CanonicalRequest) bool {
		return applyTransformedMessages(creq, payload)
	})
}

func rewriteRequestWith(reg *adapter.Registry, format adapter.Format, original []byte, creq *adapter.CanonicalRequest, apply func(*adapter.CanonicalRequest) bool) ([]byte, bool) {
	if reg == nil || creq == nil {
		return nil, false
	}
	before, beforeArgs := requestParts(creq), requestToolArguments(creq)
	if !apply(creq) {
		return nil, false
	}
	if original != nil && slices.Equal(before, requestParts(creq)) && slices.Equal(beforeArgs, requestToolArguments(creq)) {
		return original, true
	}
	adp, err := reg.GetAdapter(format)
	if err != nil {
		return nil, false
	}
	body, err := adp.EncodeRequest(creq)
	if err != nil {
		return nil, false
	}
	return body, true
}

func rewriteResponse(reg *adapter.Registry, format adapter.Format, cresp *adapter.CanonicalResponse, masked string) ([]byte, bool) {
	if reg == nil || cresp == nil {
		return nil, false
	}
	cresp.Content = masked
	adp, err := reg.GetAdapter(format)
	if err != nil {
		return nil, false
	}
	body, err := adp.EncodeResponse(cresp)
	if err != nil {
		return nil, false
	}
	return body, true
}

// rewriteResponseFromPayload is rewriteResponse for the messages[] payload
// TrustGuard echoes on a protocol=llm response transform. The text comes from
// the joined content as before; the tool call arguments are mapped back by
// position, because a secret in a call's arguments is masked there and nowhere
// else. An echo that carries a tool_calls list of another length fails rather
// than forwarding the call with the secret intact.
func rewriteResponseFromPayload(reg *adapter.Registry, format adapter.Format, cresp *adapter.CanonicalResponse, payload map[string]any) ([]byte, bool) {
	if reg == nil || cresp == nil {
		return nil, false
	}
	hasText := strings.TrimSpace(cresp.Content) != ""
	var masked string
	if hasText {
		var ok bool
		if masked, ok = transformedInput(payload); !ok {
			return nil, false
		}
	}
	var writes []func()
	if len(cresp.ToolCalls) > 0 {
		// The arguments travel only in messages[]; a legacy "input" echo would
		// mask the text and forward them intact.
		msgs, present := payload["messages"].([]any)
		if !present || len(msgs) != 1 {
			return nil, false
		}
		msg, _ := msgs[0].(map[string]any)
		var ok bool
		if writes, ok = transformedCallArguments(cresp.ToolCalls, msg["tool_calls"]); !ok {
			return nil, false
		}
	}
	if !hasText && len(writes) == 0 {
		return nil, false
	}
	if hasText {
		cresp.Content = masked
	}
	for _, w := range writes {
		w()
	}
	adp, err := reg.GetAdapter(format)
	if err != nil {
		return nil, false
	}
	body, err := adp.EncodeResponse(cresp)
	if err != nil {
		return nil, false
	}
	return body, true
}

// applyMaskedRequest writes the masked text back into the same segments that
// joinRequestText concatenated, for a guard that answers with the legacy
// "input" string. It relies on the mask keeping the original line count, which
// a multi-line secret breaks; applyTransformedMessages is the primary path. A
// line-count mismatch means the mapping is ambiguous, so it fails rather than
// corrupting the body.
func applyMaskedRequest(creq *adapter.CanonicalRequest, masked string) bool {
	setters := requestSegmentSetters(creq)
	if len(setters) == 0 {
		return false
	}
	parts := make([]string, len(setters))
	for i, s := range setters {
		parts[i] = s.value
	}
	maskedParts, ok := redistribute(masked, parts)
	if !ok {
		return false
	}
	for i, s := range setters {
		s.set(maskedParts[i])
	}
	return true
}

// applyTransformedMessages writes TrustGuard's masked messages[] back into the
// request by position. guardChatMessages sends the trimmed system prompt (when
// non-empty) followed by every message, and TrustGuard masks string leaves in
// place, so entry i of the echo is entry i of what was sent. Mapping by position
// rather than by line count means a mask that changes the newline structure (a
// multi-line private key becomes one token) or a system prompt with surrounding
// whitespace no longer degrades a transform into a block. Any shape mismatch
// still fails, and nothing is written unless every entry maps.
func applyTransformedMessages(creq *adapter.CanonicalRequest, payload map[string]any) bool {
	arr, ok := payload["messages"].([]any)
	if !ok {
		return false
	}
	offset := 0
	if strings.TrimSpace(creq.System) != "" {
		offset = 1
	}
	if len(arr) != len(creq.Messages)+offset {
		return false
	}
	var writes []func()
	for i, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			return false
		}
		role, _ := m["role"].(string)
		raw, present := m["content"]
		content, isString := raw.(string)
		if present && raw != nil && !isString {
			return false
		}
		if offset == 1 && i == 0 {
			if role != "system" || !isString {
				return false
			}
			writes = append(writes, func() { creq.System = rewrapSpace(creq.System, content) })
			continue
		}
		msg := &creq.Messages[i-offset]
		if role != msg.Role {
			return false
		}
		if isString && strings.TrimSpace(msg.Content) != "" {
			writes = append(writes, func() { msg.Content = content })
		}
		argWrites, ok := transformedToolArguments(msg, m["tool_calls"])
		if !ok {
			return false
		}
		writes = append(writes, argWrites...)
	}
	for _, w := range writes {
		w()
	}
	return true
}

// transformedToolArguments maps the echoed tool_calls of one message back onto
// its canonical tool calls. TrustGuard masks secrets inside the arguments too,
// and dropping them would forward the call with the secret intact while the
// span says transformed. TrustGuard re-marshals arguments it parses, so an
// argument is only written back when its JSON value changed, not its bytes.
func transformedToolArguments(msg *adapter.CanonicalMessage, raw any) ([]func(), bool) {
	return transformedCallArguments(msg.ToolCalls, raw)
}

func transformedCallArguments(toolCalls []adapter.CanonicalToolCall, raw any) ([]func(), bool) {
	if len(toolCalls) == 0 {
		return nil, raw == nil
	}
	calls, ok := raw.([]any)
	if !ok || len(calls) != len(toolCalls) {
		return nil, false
	}
	var writes []func()
	for j, item := range calls {
		call, _ := item.(map[string]any)
		fn, _ := call["function"].(map[string]any)
		args, ok := fn["arguments"].(string)
		if !ok {
			return nil, false
		}
		tc := &toolCalls[j]
		// An echo is matched to its call by position, so one that names a call
		// other than the one at its position was reordered, and its arguments
		// belong to another call.
		if id, named := call["id"].(string); named && id != "" && tc.ID != "" && id != tc.ID {
			return nil, false
		}
		if name, named := fn["name"].(string); named && name != "" && tc.Name != "" && name != tc.Name {
			return nil, false
		}
		if !sameJSON(tc.Arguments, args) {
			writes = append(writes, func() { tc.Arguments = args })
		}
	}
	return writes, true
}

// sameJSON reports whether a and b hold the same JSON value, or are the same
// string when either is not JSON (a custom tool's freeform input).
func sameJSON(a, b string) bool {
	if a == b {
		return true
	}
	var va, vb any
	if decodeJSON(a, &va) != nil || decodeJSON(b, &vb) != nil {
		return false
	}
	return reflect.DeepEqual(va, vb)
}

func decodeJSON(s string, v *any) error {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// requestToolArguments lists every tool call's arguments in order, so a
// transform that masked only an argument is not taken for an unchanged body.
func requestToolArguments(creq *adapter.CanonicalRequest) []string {
	var out []string
	for _, msg := range creq.Messages {
		for _, tc := range msg.ToolCalls {
			out = append(out, tc.Arguments)
		}
	}
	return out
}

// rewrapSpace restores the leading and trailing whitespace guardChatMessages
// trimmed off original before sending it, so an unmasked system prompt comes
// back byte-identical.
func rewrapSpace(original, masked string) string {
	trimmed := strings.TrimSpace(original)
	start := strings.Index(original, trimmed)
	return original[:start] + masked + original[start+len(trimmed):]
}

type segmentSetter struct {
	value string
	set   func(string)
}

func requestSegmentSetters(creq *adapter.CanonicalRequest) []segmentSetter {
	setters := make([]segmentSetter, 0, len(creq.Messages)+1)
	if strings.TrimSpace(creq.System) != "" {
		setters = append(setters, segmentSetter{
			value: creq.System,
			set:   func(s string) { creq.System = s },
		})
	}
	for i := range creq.Messages {
		i := i
		if strings.TrimSpace(creq.Messages[i].Content) != "" {
			setters = append(setters, segmentSetter{
				value: creq.Messages[i].Content,
				set:   func(s string) { creq.Messages[i].Content = s },
			})
		}
	}
	return setters
}

// redistribute splits the newline-joined masked text back into one entry per
// original part, preserving each part's original line count. It returns false
// when the total line count differs, which signals that the masking altered the
// newline structure and the mapping can no longer be trusted.
func redistribute(masked string, parts []string) ([]string, bool) {
	maskedLines := strings.Split(masked, "\n")
	counts := make([]int, len(parts))
	total := 0
	for i, part := range parts {
		counts[i] = strings.Count(part, "\n") + 1
		total += counts[i]
	}
	if total != len(maskedLines) {
		return nil, false
	}
	out := make([]string, len(parts))
	idx := 0
	for i, count := range counts {
		out[i] = strings.Join(maskedLines[idx:idx+count], "\n")
		idx += count
	}
	return out, true
}
