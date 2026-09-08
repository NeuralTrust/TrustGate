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

package mcp

import (
	"encoding/json"
	"testing"
)

func decodeJSON(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return out
}

func TestBoundTaskStatusAndTerminal(t *testing.T) {
	t.Parallel()
	for _, known := range taskStatuses {
		if got := BoundTaskStatus(string(known)); got != known {
			t.Fatalf("BoundTaskStatus(%q) = %q", known, got)
		}
	}
	for _, unknown := range []string{"", "pending", "WORKING", "completed "} {
		if got := BoundTaskStatus(unknown); got != "" {
			t.Fatalf("BoundTaskStatus(%q) = %q, want empty", unknown, got)
		}
	}
	terminal := map[TaskStatus]bool{
		TaskStatusWorking:       false,
		TaskStatusInputRequired: false,
		TaskStatusCompleted:     true,
		TaskStatusCancelled:     true,
		TaskStatusFailed:        true,
	}
	for status, want := range terminal {
		if got := status.Terminal(); got != want {
			t.Fatalf("%q.Terminal() = %v, want %v", status, got, want)
		}
	}
}

// An upstream on a draft revision may send fields TrustGate has never heard of.
// They have to survive the round trip, exactly as Tool and Prompt do.
func TestTask_UnknownFieldsRoundTrip(t *testing.T) {
	t.Parallel()
	raw := `{"taskId":"u-1","status":"working","createdAt":"2026-01-01T00:00:00Z",` +
		`"ttlMs":600000,"pollIntervalMs":250,"futureField":{"nested":[1,2]}}`
	var task Task
	if err := json.Unmarshal([]byte(raw), &task); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if task.TaskID != "u-1" || task.Status != TaskStatusWorking || task.CreatedAt != "2026-01-01T00:00:00Z" {
		t.Fatalf("task = %+v", task)
	}
	if task.TTLMs == nil || *task.TTLMs != 600000 {
		t.Fatalf("ttlMs = %v", task.TTLMs)
	}
	if task.PollIntervalMs == nil || *task.PollIntervalMs != 250 {
		t.Fatalf("pollIntervalMs = %v", task.PollIntervalMs)
	}
	encoded, err := json.Marshal(task)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decoded := decodeJSON(t, encoded)
	if _, ok := decoded["futureField"]; !ok {
		t.Fatalf("unknown field dropped: %s", encoded)
	}
	if decoded["ttlMs"] != float64(600000) || decoded["pollIntervalMs"] != float64(250) {
		t.Fatalf("numeric fields = %v", decoded)
	}
}

func TestCreateTaskResult_RoundTrip(t *testing.T) {
	t.Parallel()
	raw := `{"resultType":"task","taskId":"u-1","status":"working","ttlMs":1000,"extra":"keep"}`
	var result CreateTaskResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.ResultType != ResultTypeTask || result.TaskID != "u-1" {
		t.Fatalf("result = %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	decoded := decodeJSON(t, encoded)
	if decoded["resultType"] != ResultTypeTask || decoded["extra"] != "keep" {
		t.Fatalf("encoded = %s", encoded)
	}
}

func TestDetailedTask_CarriesExactlyWhatUpstreamSent(t *testing.T) {
	t.Parallel()
	var detailed DetailedTask
	raw := `{"taskId":"u-1","status":"completed","result":{"content":[{"type":"text","text":"hi"}]}}`
	if err := json.Unmarshal([]byte(raw), &detailed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if detailed.Status != TaskStatusCompleted || len(detailed.Result) == 0 {
		t.Fatalf("detailed = %+v", detailed)
	}
	if detailed.Error != nil || detailed.InputRequests != nil {
		t.Fatalf("absent fields must stay nil: %+v", detailed)
	}
}

func TestTaskResultFields(t *testing.T) {
	t.Parallel()
	resultType, status, taskID, ok := TaskResultFields(json.RawMessage(
		`{"resultType":"task","status":"working","taskId":"u-1"}`))
	if !ok || resultType != ResultTypeTask || status != TaskStatusWorking || taskID != "u-1" {
		t.Fatalf("fields = %q %q %q %v", resultType, status, taskID, ok)
	}
	if _, _, _, ok := TaskResultFields(json.RawMessage(`[]`)); ok {
		t.Fatal("a non-object payload must not report ok")
	}
	if _, _, _, ok := TaskResultFields(json.RawMessage(`{"content":[]}`)); !ok {
		t.Fatal("an ordinary tool result is still a JSON object")
	}
}

// The floor is applied whether or not the upstream expressed a preference, and
// the handle always replaces the upstream id.
func TestRewriteTaskEnvelope_PollFloorAndHandleSwap(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		raw      string
		floor    int64
		wantPoll float64
	}{
		{"upstream omits it", `{"resultType":"task","taskId":"u-1","status":"working"}`, 1000, 1000},
		{"upstream below the floor", `{"taskId":"u-1","pollIntervalMs":250}`, 1000, 1000},
		{"upstream above the floor", `{"taskId":"u-1","pollIntervalMs":5000}`, 1000, 5000},
		{"floor disabled", `{"taskId":"u-1"}`, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out := RewriteTaskEnvelope(json.RawMessage(tc.raw), "tg1k.c.handle.mac", tc.floor)
			decoded := decodeJSON(t, out)
			if decoded["taskId"] != "tg1k.c.handle.mac" {
				t.Fatalf("taskId = %v", decoded["taskId"])
			}
			if decoded["pollIntervalMs"] != tc.wantPoll {
				t.Fatalf("pollIntervalMs = %v, want %v", decoded["pollIntervalMs"], tc.wantPoll)
			}
		})
	}
}

func TestRewriteTaskEnvelope_PreservesSiblings(t *testing.T) {
	t.Parallel()
	out := RewriteTaskEnvelope(json.RawMessage(
		`{"resultType":"task","taskId":"u-1","status":"working","ttlMs":600000,"extra":"keep"}`),
		"handle", 1000)
	decoded := decodeJSON(t, out)
	if decoded["resultType"] != ResultTypeTask || decoded["ttlMs"] != float64(600000) || decoded["extra"] != "keep" {
		t.Fatalf("rewritten = %s", out)
	}
}

func TestRewriteTaskEnvelope_NonObjectIsUntouched(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`"not an object"`)
	if got := RewriteTaskEnvelope(raw, "handle", 1000); string(got) != string(raw) {
		t.Fatalf("got = %s", got)
	}
}

func TestTerminalTaskResultAndReplace(t *testing.T) {
	t.Parallel()
	completed := json.RawMessage(`{"taskId":"h","status":"completed","result":{"content":[{"type":"text"}]}}`)
	inner, ok := TerminalTaskResult(completed)
	if !ok {
		t.Fatal("a completed task carrying a result must expose it")
	}
	if string(inner) != `{"content":[{"type":"text"}]}` {
		t.Fatalf("inner = %s", inner)
	}

	for _, raw := range []string{
		`{"status":"working"}`,
		`{"status":"completed"}`,
		`{"status":"failed","error":{"code":1}}`,
		`{"status":"cancelled"}`,
		`[]`,
	} {
		if _, ok := TerminalTaskResult(json.RawMessage(raw)); ok {
			t.Fatalf("%s must not yield a terminal tool result", raw)
		}
	}

	replaced := ReplaceTaskResult(completed, json.RawMessage(`{"content":[{"type":"text","text":"[REDACTED]"}]}`))
	decoded := decodeJSON(t, replaced)
	if decoded["status"] != "completed" {
		t.Fatalf("splicing must keep the envelope: %s", replaced)
	}
	inner, ok = TerminalTaskResult(replaced)
	if !ok || string(inner) != `{"content":[{"type":"text","text":"[REDACTED]"}]}` {
		t.Fatalf("spliced result = %s", inner)
	}
}

// A non-declaring client, or a gateway with the feature off, must never see a
// taskId it cannot poll.
func TestStripTaskResult(t *testing.T) {
	t.Parallel()
	out := StripTaskResult(json.RawMessage(
		`{"resultType":"task","taskId":"u-1","status":"working","ttlMs":1,"pollIntervalMs":2,` +
			`"createdAt":"x","lastUpdatedAt":"y","content":[]}`))
	decoded := decodeJSON(t, out)
	if decoded["resultType"] != "complete" {
		t.Fatalf("resultType = %v", decoded["resultType"])
	}
	for _, key := range []string{"taskId", "status", "ttlMs", "pollIntervalMs", "createdAt", "lastUpdatedAt"} {
		if _, ok := decoded[key]; ok {
			t.Fatalf("%q survived the strip: %s", key, out)
		}
	}
	if _, ok := decoded["content"]; !ok {
		t.Fatalf("the tool payload must survive: %s", out)
	}
}

// The extensions object must survive the capability allowlist, bounded to the
// tasks key with an empty value: dropping it destroyed the client's declaration,
// and forwarding it verbatim would let a client smuggle a payload southbound.
func TestAllowlistedClientCapabilities_BoundsExtensions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  map[string]any
		want map[string]any
	}{
		{
			name: "tasks declaration is kept and emptied",
			raw: map[string]any{
				"elicitation": map[string]any{},
				CapabilityKindExtensions: map[string]any{
					MetaKeyTasksExtension: map[string]any{"smuggled": "payload"},
				},
			},
			want: map[string]any{
				"elicitation": map[string]any{},
				CapabilityKindExtensions: map[string]any{
					MetaKeyTasksExtension: map[string]any{},
				},
			},
		},
		{
			name: "unknown extensions are dropped",
			raw: map[string]any{
				CapabilityKindExtensions: map[string]any{"vendor/other": map[string]any{}},
			},
			want: nil,
		},
		{
			name: "a non-object extensions value is dropped",
			raw:  map[string]any{CapabilityKindExtensions: "tasks"},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := AllowlistedClientCapabilities(tt.raw)
			if tt.want == nil {
				if got != nil {
					t.Fatalf("capabilities = %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("capabilities = %v, want %v", got, tt.want)
			}
			if !DeclaredTasksExtension(got) {
				t.Fatalf("capabilities = %v, want the tasks extension declared", got)
			}
			extensions, ok := got[CapabilityKindExtensions].(map[string]any)
			if !ok {
				t.Fatalf("capabilities = %v, want an extensions object", got)
			}
			value, ok := extensions[MetaKeyTasksExtension].(map[string]any)
			if !ok || len(value) != 0 {
				t.Fatalf("extensions = %v, want an empty tasks object", extensions)
			}
		})
	}
}

// A client that declared nothing, or only other capabilities, has not declared
// the extension.
func TestDeclaredTasksExtension_RequiresTheKey(t *testing.T) {
	t.Parallel()
	if DeclaredTasksExtension(nil) {
		t.Fatal("no capabilities cannot declare the extension")
	}
	if DeclaredTasksExtension(map[string]any{"elicitation": map[string]any{}}) {
		t.Fatal("elicitation is not the tasks extension")
	}
}
