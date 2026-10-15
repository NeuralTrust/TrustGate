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
	"encoding/json"
	"strings"
	"testing"
)

func TestModelRejectsReasoningEffortNone(t *testing.T) {
	tests := []struct {
		model string
		want  bool
	}{
		{model: "gpt-6.1-sol", want: true},
		{model: "GPT-6.1-Sol", want: true},
		{model: "openai/gpt-6.1-sol", want: true},
		{model: "ft:gpt-6.1-sol:org::id", want: true},
		{model: "gpt-6.1-sol-2026-10-01", want: true},
		{model: "gpt-6-astra", want: true},
		{model: "gpt-6-astra-2026-08-01", want: true},
		{model: "gpt-6-sol", want: false},
		{model: "gpt-6-luna", want: false},
		{model: "gpt-5.6-sol", want: false},
		{model: "gpt-5.6-luna", want: false},
		{model: "gpt-6.10-sol", want: false},
		{model: "gpt-4.1-nano", want: false},
		{model: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			if got := ModelRejectsReasoningEffortNone(tt.model); got != tt.want {
				t.Fatalf("ModelRejectsReasoningEffortNone(%q) = %v, want %v", tt.model, got, tt.want)
			}
		})
	}
}

func TestOmitUnsupportedReasoningEffort(t *testing.T) {
	const withNone = `{"model":"gpt-6.1-sol","messages":[],"tools":[{"type":"function","function":{"name":"qa_escalate"}}],"reasoning_effort":"none"}`
	out := OmitUnsupportedReasoningEffort([]byte(withNone), "gpt-6.1-sol")
	if strings.Contains(string(out), `"reasoning_effort"`) {
		t.Fatalf("none kept for gpt-6.1-sol: %s", out)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed["tools"] == nil {
		t.Fatalf("tools dropped: %s", out)
	}

	const kept = `{"model":"gpt-5.6-luna","reasoning_effort":"none","tools":[{"type":"function"}]}`
	if got := string(OmitUnsupportedReasoningEffort([]byte(kept), "gpt-5.6-luna")); got != kept {
		t.Fatalf("luna body changed: %s", got)
	}

	const high = `{"model":"gpt-6.1-sol","reasoning_effort":"high"}`
	if got := string(OmitUnsupportedReasoningEffort([]byte(high), "gpt-6.1-sol")); got != high {
		t.Fatalf("high effort changed: %s", got)
	}

	const absent = `{"model":"gpt-6.1-sol","messages":[]}`
	if got := string(OmitUnsupportedReasoningEffort([]byte(absent), "gpt-6.1-sol")); got != absent {
		t.Fatalf("absent effort changed: %s", got)
	}
}
