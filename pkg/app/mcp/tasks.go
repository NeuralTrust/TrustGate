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
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

// MetaKeyTasksExtension is the io.modelcontextprotocol/tasks extension key, used
// both as a capability name and as the southbound _meta key.
const MetaKeyTasksExtension = "io.modelcontextprotocol/tasks"

const (
	MethodTasksGet    = "tasks/get"
	MethodTasksUpdate = "tasks/update"
	MethodTasksCancel = "tasks/cancel"
)

// ResultTypeTask marks a tools/call result that created a task instead of
// producing the tool's output.
const ResultTypeTask = "task"

// TaskStatus is a task's lifecycle state as reported by the upstream.
type TaskStatus string

const (
	TaskStatusWorking       TaskStatus = "working"
	TaskStatusInputRequired TaskStatus = "input_required"
	TaskStatusCompleted     TaskStatus = "completed"
	TaskStatusCancelled     TaskStatus = "cancelled"
	TaskStatusFailed        TaskStatus = "failed"
)

var taskStatuses = []TaskStatus{
	TaskStatusWorking,
	TaskStatusInputRequired,
	TaskStatusCompleted,
	TaskStatusCancelled,
	TaskStatusFailed,
}

// BoundTaskStatus keeps only the statuses the extension defines, returning "" for
// anything else so an upstream cannot widen a telemetry label set.
func BoundTaskStatus(raw string) TaskStatus {
	for _, known := range taskStatuses {
		if TaskStatus(raw) == known {
			return known
		}
	}
	return ""
}

// Terminal reports whether no further transition is possible.
func (s TaskStatus) Terminal() bool {
	switch s {
	case TaskStatusCompleted, TaskStatusCancelled, TaskStatusFailed:
		return true
	default:
		return false
	}
}

// Task is the extension's Task shape. Unknown upstream fields round-trip so a
// draft revision can add fields without TrustGate dropping them.
type Task struct {
	TaskID         string
	Status         TaskStatus
	CreatedAt      string
	LastUpdatedAt  string
	TTLMs          *int64
	PollIntervalMs *int64

	payload map[string]json.RawMessage
}

func (t Task) MarshalJSON() ([]byte, error) {
	out, err := marshalEnvelope(t.payload,
		"taskId", t.TaskID,
		"status", string(t.Status),
	)
	if err != nil {
		return nil, err
	}
	return applyTaskNumbers(out, t.TTLMs, t.PollIntervalMs)
}

func (t *Task) UnmarshalJSON(data []byte) error {
	payload, err := unmarshalEnvelope(data)
	if err != nil {
		return fmt.Errorf("mcp: decode task: %w", err)
	}
	t.payload = payload
	t.TaskID = stringField(payload, "taskId")
	t.Status = TaskStatus(stringField(payload, "status"))
	t.CreatedAt = stringField(payload, "createdAt")
	t.LastUpdatedAt = stringField(payload, "lastUpdatedAt")
	t.TTLMs = numberField(payload, "ttlMs")
	t.PollIntervalMs = numberField(payload, "pollIntervalMs")
	return nil
}

// CreateTaskResult is a tools/call result that created a task.
type CreateTaskResult struct {
	Task

	ResultType string
}

func (r CreateTaskResult) MarshalJSON() ([]byte, error) {
	encoded, err := r.Task.MarshalJSON()
	if err != nil {
		return nil, err
	}
	fields, err := unmarshalEnvelope(encoded)
	if err != nil {
		return nil, err
	}
	return marshalEnvelope(fields, "resultType", r.ResultType)
}

func (r *CreateTaskResult) UnmarshalJSON(data []byte) error {
	if err := r.Task.UnmarshalJSON(data); err != nil {
		return err
	}
	r.ResultType = stringField(r.payload, "resultType")
	return nil
}

// DetailedTask is a tasks/get result: a task plus at most one of result, error,
// or inputRequests depending on its status.
type DetailedTask struct {
	Task

	Result        json.RawMessage
	Error         json.RawMessage
	InputRequests json.RawMessage
}

func (d *DetailedTask) UnmarshalJSON(data []byte) error {
	if err := d.Task.UnmarshalJSON(data); err != nil {
		return err
	}
	d.Result = d.payload["result"]
	d.Error = d.payload["error"]
	d.InputRequests = d.payload["inputRequests"]
	return nil
}

// numberField reads a nullable JSON number that marshalEnvelope's string-only
// signature cannot carry.
func numberField(payload map[string]json.RawMessage, key string) *int64 {
	raw, ok := payload[key]
	if !ok {
		return nil
	}
	var value int64
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil
	}
	return &value
}

func applyTaskNumbers(encoded []byte, ttlMs, pollIntervalMs *int64) ([]byte, error) {
	if ttlMs == nil && pollIntervalMs == nil {
		return encoded, nil
	}
	fields, err := unmarshalEnvelope(encoded)
	if err != nil {
		return nil, err
	}
	if ttlMs != nil {
		fields["ttlMs"] = json.RawMessage(formatInt64(*ttlMs))
	}
	if pollIntervalMs != nil {
		fields["pollIntervalMs"] = json.RawMessage(formatInt64(*pollIntervalMs))
	}
	return json.Marshal(fields)
}

func formatInt64(value int64) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "0"
	}
	return string(encoded)
}

// TaskResultFields reads the discriminating fields of a raw upstream result
// without decoding the whole envelope. ok is false when the payload is not a
// JSON object.
func TaskResultFields(raw json.RawMessage) (resultType string, status TaskStatus, taskID string, ok bool) {
	fields, err := unmarshalEnvelope(raw)
	if err != nil {
		return "", "", "", false
	}
	return stringField(fields, "resultType"),
		TaskStatus(stringField(fields, "status")),
		stringField(fields, "taskId"),
		true
}

// RewriteTaskEnvelope swaps the upstream taskId for the handle the client must
// echo and clamps pollIntervalMs to the configured floor, always emitting it.
// It never mints: the caller supplies the handle so it stays stable across polls.
func RewriteTaskEnvelope(raw json.RawMessage, handle string, pollFloorMs int64) json.RawMessage {
	fields, err := unmarshalEnvelope(raw)
	if err != nil {
		return raw
	}
	encodedHandle, err := json.Marshal(handle)
	if err != nil {
		return raw
	}
	fields["taskId"] = encodedHandle
	poll := pollFloorMs
	if upstream := numberField(fields, "pollIntervalMs"); upstream != nil && *upstream > poll {
		poll = *upstream
	}
	if poll < 0 {
		poll = 0
	}
	fields["pollIntervalMs"] = json.RawMessage(formatInt64(poll))
	out, err := json.Marshal(fields)
	if err != nil {
		return raw
	}
	return out
}

// TerminalTaskResult extracts the tool result a completed task carries, so the
// response plugin stage can see the payload a task delivery would otherwise
// smuggle past it.
func TerminalTaskResult(raw json.RawMessage) (json.RawMessage, bool) {
	fields, err := unmarshalEnvelope(raw)
	if err != nil {
		return nil, false
	}
	if BoundTaskStatus(stringField(fields, "status")) != TaskStatusCompleted {
		return nil, false
	}
	result, ok := fields["result"]
	if !ok || len(result) == 0 {
		return nil, false
	}
	return result, true
}

// ReplaceTaskResult splices a rewritten tool result back into a task envelope.
func ReplaceTaskResult(raw, result json.RawMessage) json.RawMessage {
	fields, err := unmarshalEnvelope(raw)
	if err != nil {
		return raw
	}
	fields["result"] = result
	out, err := json.Marshal(fields)
	if err != nil {
		return raw
	}
	return out
}

// StripTaskResult turns a task-shaped result into an ordinary one. It is the
// fallback for a client that never declared the extension and for a gateway with
// task mediation disabled: neither can be handed a taskId it cannot use.
func StripTaskResult(raw json.RawMessage) json.RawMessage {
	fields, err := unmarshalEnvelope(raw)
	if err != nil {
		return raw
	}
	for _, key := range []string{"taskId", "status", "ttlMs", "pollIntervalMs", "createdAt", "lastUpdatedAt"} {
		delete(fields, key)
	}
	complete, err := json.Marshal(trace.MRTROutcomeComplete)
	if err != nil {
		return raw
	}
	fields["resultType"] = complete
	out, err := json.Marshal(fields)
	if err != nil {
		return raw
	}
	return out
}
