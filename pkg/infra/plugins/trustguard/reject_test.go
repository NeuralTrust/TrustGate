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

	raw := blockBody(&GuardResponse{
		Status: statusBlock,
		Findings: []GuardFinding{{
			Source:  &GuardFindingSource{Kind: "detector", Plugin: "prompt_guard"},
			Signal:  &GuardFindingSignal{Type: "jailbreak", Confidence: 0.99},
			Outcome: &GuardFindingOutcome{Action: "block"},
			Evidence: map[string]any{
				"policy_id":   "policy-1",
				"detector_id": "detector-1",
			},
		}},
		TraceID:   "trace-1",
		RequestID: "req-1",
	})

	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("unmarshal block body: %v", err)
	}
	if _, ok := body["findings"]; ok {
		t.Fatalf("client block body must not include findings, got %s", string(raw))
	}

	var status, message, traceID, requestID string
	if err := json.Unmarshal(body["status"], &status); err != nil {
		t.Fatalf("status: %v", err)
	}
	if err := json.Unmarshal(body["message"], &message); err != nil {
		t.Fatalf("message: %v", err)
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
	if message != blockMessage {
		t.Fatalf("message = %q, want %q", message, blockMessage)
	}
	if traceID != "trace-1" || requestID != "req-1" {
		t.Fatalf("trace/request ids = %q / %q", traceID, requestID)
	}
}
