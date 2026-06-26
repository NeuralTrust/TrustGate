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

package bedrockguardrail

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

const unsupportedFormat adapter.Format = "does-not-exist"

func TestMaskedText(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		out  *bedrockruntime.ApplyGuardrailOutput
		want string
		ok   bool
	}{
		{"nil output", nil, "", false},
		{"empty outputs", &bedrockruntime.ApplyGuardrailOutput{}, "", false},
		{"nil text", &bedrockruntime.ApplyGuardrailOutput{Outputs: []types.GuardrailOutputContent{{}}}, "", false},
		{"empty text", &bedrockruntime.ApplyGuardrailOutput{Outputs: []types.GuardrailOutputContent{{Text: aws.String("")}}}, "", false},
		{"masked", &bedrockruntime.ApplyGuardrailOutput{Outputs: []types.GuardrailOutputContent{{Text: aws.String("hi {EMAIL}")}}}, "hi {EMAIL}", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := maskedText(tt.out)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("maskedText = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestRewriteRequestRoundTrip(t *testing.T) {
	t.Parallel()
	reg := adapter.NewRegistry()
	creq := &adapter.CanonicalRequest{
		Model: "gpt-4o",
		Messages: []adapter.CanonicalMessage{
			{Role: "system", Content: "be safe"},
			{Role: roleUser, Content: "my email is john@example.com"},
		},
	}
	body, ok := rewriteRequest(reg, adapter.FormatOpenAI, creq, 1, "my email is {EMAIL}")
	if !ok || len(body) == 0 {
		t.Fatalf("rewriteRequest ok = %v, len = %d", ok, len(body))
	}
	decoded, err := reg.DecodeRequestFor(body, adapter.FormatOpenAI)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, idx := lastUserText(decoded)
	if idx < 0 || got != "my email is {EMAIL}" {
		t.Fatalf("rewritten user content = %q (idx %d)", got, idx)
	}
}

func TestRewriteRequestUnsupportedFormat(t *testing.T) {
	t.Parallel()
	reg := adapter.NewRegistry()
	creq := &adapter.CanonicalRequest{
		Messages: []adapter.CanonicalMessage{{Role: roleUser, Content: "hello"}},
	}
	if body, ok := rewriteRequest(reg, unsupportedFormat, creq, 0, "masked"); ok || body != nil {
		t.Fatalf("expected (nil,false) on unsupported format, got (%v,%v)", body, ok)
	}
}

func TestRewriteRequestOutOfBounds(t *testing.T) {
	t.Parallel()
	reg := adapter.NewRegistry()
	creq := &adapter.CanonicalRequest{
		Messages: []adapter.CanonicalMessage{{Role: roleUser, Content: "hello"}},
	}
	if body, ok := rewriteRequest(reg, adapter.FormatOpenAI, creq, 5, "masked"); ok || body != nil {
		t.Fatalf("expected (nil,false) on out-of-bounds index, got (%v,%v)", body, ok)
	}
}

func TestRewriteResponseRoundTrip(t *testing.T) {
	t.Parallel()
	reg := adapter.NewRegistry()
	cresp := &adapter.CanonicalResponse{
		ID:      "r1",
		Model:   "gpt-4o",
		Role:    "assistant",
		Content: "the ssn is 123-45-6789",
	}
	body, ok := rewriteResponse(reg, adapter.FormatOpenAI, cresp, "the ssn is {SSN}")
	if !ok || len(body) == 0 {
		t.Fatalf("rewriteResponse ok = %v, len = %d", ok, len(body))
	}
	decoded, err := reg.DecodeResponseFor(body, adapter.FormatOpenAI)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Content != "the ssn is {SSN}" {
		t.Fatalf("rewritten content = %q", decoded.Content)
	}
}

func TestRewriteResponseUnsupportedFormat(t *testing.T) {
	t.Parallel()
	reg := adapter.NewRegistry()
	cresp := &adapter.CanonicalResponse{Content: "hello"}
	if body, ok := rewriteResponse(reg, unsupportedFormat, cresp, "masked"); ok || body != nil {
		t.Fatalf("expected (nil,false) on unsupported format, got (%v,%v)", body, ok)
	}
}

func TestSupportsReencode(t *testing.T) {
	t.Parallel()
	reg := adapter.NewRegistry()
	if !supportsReencode(reg, adapter.FormatOpenAI) {
		t.Fatal("expected openai format to support re-encode")
	}
	if supportsReencode(reg, unsupportedFormat) {
		t.Fatal("expected unsupported format to not support re-encode")
	}
	if supportsReencode(nil, adapter.FormatOpenAI) {
		t.Fatal("expected nil registry to not support re-encode")
	}
}
