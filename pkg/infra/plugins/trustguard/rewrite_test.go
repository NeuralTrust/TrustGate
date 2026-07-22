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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func TestRedistributePreservesMultilineSegments(t *testing.T) {
	t.Parallel()

	parts := []string{"be safe", "line one\nline two", "final"}
	masked := strings.Join(parts, "\n")
	masked = strings.Replace(masked, "line two", "[MASKED] two", 1)

	out, ok := redistribute(masked, parts)
	if !ok {
		t.Fatal("redistribute must succeed when newline count is preserved")
	}
	if len(out) != len(parts) {
		t.Fatalf("got %d parts, want %d", len(out), len(parts))
	}
	if out[0] != "be safe" || out[2] != "final" {
		t.Fatalf("unmatched segments altered: %#v", out)
	}
	if out[1] != "line one\n[MASKED] two" {
		t.Fatalf("multiline segment = %q, want %q", out[1], "line one\n[MASKED] two")
	}
}

func TestRedistributeRejectsLineCountChange(t *testing.T) {
	t.Parallel()

	parts := []string{"one", "two"}
	if _, ok := redistribute("one\ntwo\nextra", parts); ok {
		t.Fatal("redistribute must reject a changed newline count")
	}
}

func TestApplyMaskedRequestMapsSystemAndMessages(t *testing.T) {
	t.Parallel()

	creq := &adapter.CanonicalRequest{
		System: "be safe",
		Messages: []adapter.CanonicalMessage{
			{Role: "user", Content: "email me at a@b.com"},
			{Role: "assistant", Content: ""},
			{Role: "user", Content: "thanks"},
		},
	}
	masked := "be safe\nemail me at [MASKED_EMAIL]\nthanks"

	if !applyMaskedRequest(creq, masked) {
		t.Fatal("applyMaskedRequest must succeed")
	}
	if creq.System != "be safe" {
		t.Fatalf("system = %q, want unchanged", creq.System)
	}
	if creq.Messages[0].Content != "email me at [MASKED_EMAIL]" {
		t.Fatalf("message[0] = %q, want masked", creq.Messages[0].Content)
	}
	if creq.Messages[1].Content != "" {
		t.Fatalf("empty message must stay empty, got %q", creq.Messages[1].Content)
	}
	if creq.Messages[2].Content != "thanks" {
		t.Fatalf("message[2] = %q, want unchanged", creq.Messages[2].Content)
	}
}
