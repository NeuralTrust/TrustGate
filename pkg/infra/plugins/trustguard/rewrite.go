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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// transformTarget carries the closure that applies TrustGuard's masked text back
// into the provider body for the current direction. apply is nil when the path
// (e.g. native MCP) cannot propagate a rewritten body.
type transformTarget struct {
	isResponse bool
	apply      func(masked string) ([]byte, bool)
}

// transformedInput extracts the masked string TrustGuard returns under the
// payload's "input" key. TrustGate always sends a minimal {input: text} payload,
// so the transform mirrors that shape.
func transformedInput(payload map[string]any) (string, bool) {
	if payload == nil {
		return "", false
	}
	value, ok := payload[transformedInputKey]
	if !ok {
		return "", false
	}
	masked, ok := value.(string)
	return masked, ok
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

func rewriteRequest(reg *adapter.Registry, format adapter.Format, creq *adapter.CanonicalRequest, masked string) ([]byte, bool) {
	if reg == nil || creq == nil {
		return nil, false
	}
	if !applyMaskedRequest(creq, masked) {
		return nil, false
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

// applyMaskedRequest writes the masked text back into the same segments that
// joinRequestText concatenated. TrustGuard masks only detected spans and never
// adds or removes newlines, so the masked text keeps the original line count and
// can be split back into the per-segment values. A line-count mismatch means the
// mapping is ambiguous, so it fails rather than corrupting the body.
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
