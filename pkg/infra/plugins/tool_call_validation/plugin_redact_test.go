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

package tool_call_validation

import (
	"context"
	"net/http"
	"strings"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func TestExecuteRegexRejectReturns502(t *testing.T) {
	t.Parallel()

	settings := map[string]any{
		"rules": []any{
			map[string]any{
				"tool":          "send_email",
				"validator":     "regex",
				"argument_path": "$.to",
				"pattern":       `^.+@company\.com$`,
				"behavior":      "reject_response",
			},
		},
	}
	p := New(adapter.NewRegistry(), nil, nil)
	in := newExecInput(
		settings,
		openAIRequest(),
		&infracontext.ResponseContext{StatusCode: 200, Body: openAIResponseWithToolCall("send_email", `{"to":"attacker@evil.com"}`)},
	)

	res, err := p.Execute(context.Background(), in)
	if res != nil {
		t.Fatalf("expected nil result on reject, got %+v", res)
	}
	pe, ok := appplugins.AsPluginError(err)
	if !ok {
		t.Fatalf("expected *PluginError, got %v", err)
	}
	if pe.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", pe.StatusCode, http.StatusBadGateway)
	}
	if pe.Type != typeToolCallValidationFailed {
		t.Fatalf("type = %q, want %q", pe.Type, typeToolCallValidationFailed)
	}
}

func TestExecuteDenylistRedactReturns200(t *testing.T) {
	t.Parallel()

	settings := map[string]any{
		"rules": []any{
			map[string]any{
				"tool":          "send_email",
				"validator":     "denylist",
				"argument_path": "$.code",
				"denylist":      []any{"rm -rf"},
				"behavior":      "redact",
			},
		},
	}
	p := New(adapter.NewRegistry(), nil, nil)
	in := newExecInput(
		settings,
		openAIRequest(),
		&infracontext.ResponseContext{StatusCode: 200, Body: openAIResponseWithToolCall("send_email", `{"code":"sudo rm -rf /"}`)},
	)

	res, err := p.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil || res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 result, got %+v", res)
	}
	if !res.StopUpstream {
		t.Fatalf("redact result must set StopUpstream")
	}
	if len(res.Body) == 0 {
		t.Fatalf("redact result must carry a body")
	}
	calls := decodeToolCalls(t, res.Body, adapter.FormatOpenAI)
	if strings.Contains(calls[0].Arguments, "rm -rf") {
		t.Fatalf("denied substring not redacted: %s", calls[0].Arguments)
	}
	if !strings.Contains(calls[0].Arguments, defaultRedactionMarker) {
		t.Fatalf("expected redaction marker, got %s", calls[0].Arguments)
	}
}

func TestExecuteRejectPrecedenceOverRedact(t *testing.T) {
	t.Parallel()

	settings := map[string]any{
		"rules": []any{
			map[string]any{
				"tool":          "send_email",
				"validator":     "denylist",
				"argument_path": "$.code",
				"denylist":      []any{"rm -rf"},
				"behavior":      "redact",
			},
			map[string]any{
				"tool":          "send_email",
				"validator":     "regex",
				"argument_path": "$.to",
				"pattern":       `^.+@company\.com$`,
				"behavior":      "reject_response",
			},
		},
	}
	p := New(adapter.NewRegistry(), nil, nil)
	in := newExecInput(
		settings,
		openAIRequest(),
		&infracontext.ResponseContext{StatusCode: 200, Body: openAIResponseWithToolCall("send_email", `{"to":"attacker@evil.com","code":"rm -rf /"}`)},
	)

	res, err := p.Execute(context.Background(), in)
	if res != nil {
		t.Fatalf("reject must take precedence over redact, got result %+v", res)
	}
	pe, ok := appplugins.AsPluginError(err)
	if !ok {
		t.Fatalf("expected *PluginError, got %v", err)
	}
	if pe.Type != typeToolCallValidationFailed {
		t.Fatalf("type = %q, want %q", pe.Type, typeToolCallValidationFailed)
	}
}
