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
	"testing"
)

func TestBlockBodyOmitsFindingsFromClientResponse(t *testing.T) {
	t.Parallel()

	resp := &GuardResponse{
		Status: statusBlock,
		Findings: []GuardFinding{{
			Source: &GuardFindingSource{
				Kind:         "detector",
				Plugin:       "prompt_guard",
				DetectorName: "Jailbreak detector",
			},
			Signal:  &GuardFindingSignal{Type: "jailbreak", Confidence: 0.99},
			Outcome: &GuardFindingOutcome{Action: "block"},
			Evidence: map[string]any{
				"policy_id":   "policy-1",
				"detector_id": "detector-1",
			},
		}},
		TraceID:   "trace-1",
		RequestID: "req-1",
	}
	wantMessage := "Request blocked by security policy: jailbreak (Jailbreak detector)."
	raw := blockBody(resp, clientBlockMessage(resp))

	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("unmarshal block body: %v", err)
	}
	if _, ok := body["findings"]; ok {
		t.Fatalf("client block body must not include findings, got %s", string(raw))
	}
	if _, ok := body["evidence"]; ok {
		t.Fatalf("client block body must not include evidence, got %s", string(raw))
	}

	var status, message, blockType, reason, plugin, detectorName, traceID, requestID string
	if err := json.Unmarshal(body["status"], &status); err != nil {
		t.Fatalf("status: %v", err)
	}
	if err := json.Unmarshal(body["message"], &message); err != nil {
		t.Fatalf("message: %v", err)
	}
	if err := json.Unmarshal(body["type"], &blockType); err != nil {
		t.Fatalf("type: %v", err)
	}
	if err := json.Unmarshal(body["reason"], &reason); err != nil {
		t.Fatalf("reason: %v", err)
	}
	if err := json.Unmarshal(body["plugin"], &plugin); err != nil {
		t.Fatalf("plugin: %v", err)
	}
	if err := json.Unmarshal(body["detector_name"], &detectorName); err != nil {
		t.Fatalf("detector_name: %v", err)
	}
	if err := json.Unmarshal(body["trace_id"], &traceID); err != nil {
		t.Fatalf("trace_id: %v", err)
	}
	if err := json.Unmarshal(body["request_id"], &requestID); err != nil {
		t.Fatalf("request_id: %v", err)
	}
	if status != statusBlock {
		t.Fatalf("status = %q, want %q", status, statusBlock)
	}
	if message != wantMessage {
		t.Fatalf("message = %q, want %q", message, wantMessage)
	}
	if blockType != typeBlocked {
		t.Fatalf("type = %q, want %q", blockType, typeBlocked)
	}
	if reason != "jailbreak" {
		t.Fatalf("reason = %q, want jailbreak", reason)
	}
	if plugin != "prompt_guard" {
		t.Fatalf("plugin = %q, want prompt_guard", plugin)
	}
	if detectorName != "Jailbreak detector" {
		t.Fatalf("detector_name = %q, want Jailbreak detector", detectorName)
	}
	if traceID != "trace-1" || requestID != "req-1" {
		t.Fatalf("trace/request ids = %q / %q", traceID, requestID)
	}
}

func TestBlockBodyIncludesGateName(t *testing.T) {
	t.Parallel()

	resp := &GuardResponse{
		Status: statusBlock,
		Findings: []GuardFinding{{
			Source:  &GuardFindingSource{Kind: "gate", GateName: "max_tokens"},
			Signal:  &GuardFindingSignal{Type: "gate_block", Confidence: 1},
			Outcome: &GuardFindingOutcome{Action: "block"},
		}},
	}
	raw := blockBody(resp, clientBlockMessage(resp))

	var body struct {
		Type     string `json:"type"`
		Reason   string `json:"reason"`
		GateName string `json:"gate_name"`
		Message  string `json:"message"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Type != typeBlocked || body.Reason != "gate_block" || body.GateName != "max_tokens" {
		t.Fatalf("body = %+v", body)
	}
	wantMessage := "Request blocked by security policy: gate_block (max_tokens)."
	if body.Message != wantMessage {
		t.Fatalf("message = %q, want %q", body.Message, wantMessage)
	}
}

func TestClientBlockMessageFallsBackWithoutFindings(t *testing.T) {
	t.Parallel()

	if got := clientBlockMessage(nil); got != blockMessage {
		t.Fatalf("nil resp message = %q, want %q", got, blockMessage)
	}
	if got := clientBlockMessage(&GuardResponse{Status: statusBlock}); got != blockMessage {
		t.Fatalf("empty findings message = %q, want %q", got, blockMessage)
	}
}

func TestRateLimitErrorForwardsHeadersAndBody(t *testing.T) {
	t.Parallel()

	pe := rateLimitError(&rateLimitedError{
		headers: map[string][]string{
			"Retry-After":        {"7"},
			"X-RateLimit-Reason": {"quota"},
		},
		body: []byte(`{"error":"rate limit exceeded","reason":"quota"}`),
	})
	if pe.StatusCode != 429 {
		t.Fatalf("status = %d, want 429", pe.StatusCode)
	}
	if pe.Type != typeRateLimited {
		t.Fatalf("type = %q, want %q", pe.Type, typeRateLimited)
	}
	if got := pe.Headers["Retry-After"]; len(got) != 1 || got[0] != "7" {
		t.Fatalf("Retry-After = %v", got)
	}
	if string(pe.Body) != `{"error":"rate limit exceeded","reason":"quota"}` {
		t.Fatalf("body = %s", pe.Body)
	}
}

func TestRateLimitErrorEmptyBodyFallback(t *testing.T) {
	t.Parallel()

	pe := rateLimitError(&rateLimitedError{})
	if pe.StatusCode != 429 {
		t.Fatalf("status = %d, want 429", pe.StatusCode)
	}
	want := `{"error":"rate limit exceeded","message":"Request blocked: rate limit exceeded."}`
	if string(pe.Body) != want {
		t.Fatalf("body = %s, want %s", pe.Body, want)
	}
}
