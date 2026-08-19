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
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

const (
	createdTaskResult  = `{"resultType":"task","taskId":"u-123","status":"working","createdAt":"2026-01-01T00:00:00Z","ttlMs":600000}`
	workingTaskResult  = `{"taskId":"u-123","status":"working","pollIntervalMs":200}`
	completedTaskGet   = `{"taskId":"u-123","status":"completed","result":{"content":[{"type":"text","text":"done"}]}}`
	taskPollFloorMs    = 1000
	upstreamTaskCallID = "u-123"
)

// taskUpstream adds the optional task surface to the shared fake without
// touching it: an upstream that predates the extension must stay a plain
// Upstream.
type taskUpstream struct {
	*fakeUpstream

	taskResult json.RawMessage

	mu         sync.Mutex
	lastRef    TaskRef
	lastInputs json.RawMessage
	taskCalls  int
}

func (f *taskUpstream) GetTask(_ context.Context, ref TaskRef) (json.RawMessage, error) {
	f.record(ref, nil)
	return f.taskResult, nil
}

func (f *taskUpstream) UpdateTask(_ context.Context, ref TaskRef, inputs json.RawMessage) (json.RawMessage, error) {
	f.record(ref, inputs)
	return f.taskResult, nil
}

func (f *taskUpstream) CancelTask(_ context.Context, ref TaskRef) (json.RawMessage, error) {
	f.record(ref, nil)
	return f.taskResult, nil
}

func (f *taskUpstream) record(ref TaskRef, inputs json.RawMessage) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastRef = ref
	if inputs != nil {
		f.lastInputs = inputs
	}
	f.taskCalls++
}

func (f *taskUpstream) observed() (TaskRef, json.RawMessage, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastRef, f.lastInputs, f.taskCalls
}

// taskDialer counts dials per URL so a test can prove a task was routed only to
// the registry its handle names. The discovery fan-out dials concurrently, so
// the counters are guarded.
type taskDialer struct {
	mu        sync.Mutex
	upstreams map[string]Upstream
	dials     map[string]int
}

func newTaskDialer() *taskDialer {
	return &taskDialer{upstreams: map[string]Upstream{}, dials: map[string]int{}}
}

func (d *taskDialer) Connect(_ context.Context, target Target) (Upstream, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dials[target.URL]++
	up, ok := d.upstreams[target.URL]
	if !ok {
		return nil, ErrUpstreamUnavailable
	}
	return up, nil
}

func taskTestSigner() *TaskHandleSigner {
	return NewTaskHandleSigner("task-secret", "", 0, 0)
}

func newTaskComposer(dialer Dialer, tasks *TaskHandleSigner) Composer {
	return NewComposerWithMediation(
		dialer,
		nil,
		newMapCache(),
		slog.New(slog.DiscardHandler),
		testSigner(),
		tasks,
		taskPollFloorMs,
	)
}

func taskFixture(t *testing.T) (*taskUpstream, *taskDialer, *registrydomain.Registry, *consumerdomain.Consumer) {
	t.Helper()
	reg := mcpRegistry(t, "github", "https://a.example.com/mcp")
	up := &taskUpstream{
		fakeUpstream: &fakeUpstream{tools: tools("search"), result: json.RawMessage(createdTaskResult)},
		taskResult:   json.RawMessage(workingTaskResult),
	}
	dialer := newTaskDialer()
	dialer.upstreams["https://a.example.com/mcp"] = up
	return up, dialer, reg, mrtrConsumer(reg.ID, "find")
}

func mintHandle(t *testing.T, signer *TaskHandleSigner, claims TaskHandleClaims) string {
	t.Helper()
	handle, err := signer.Mint(claims)
	if err != nil {
		t.Fatalf("mint handle: %v", err)
	}
	return handle
}

// A created task must reach the client as a handle, never as the upstream's own
// task id, and the poll interval must not fall below the configured floor.
func TestComposer_CallTool_MintsTaskHandle(t *testing.T) {
	t.Parallel()
	up, dialer, reg, consumer := taskFixture(t)
	c := newTaskComposer(dialer, taskTestSigner())
	rc := routable(consumer, reg)

	result, err := c.CallTool(context.Background(), rc, ToolCall{Name: "find"})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	resultType, status, handle, ok := TaskResultFields(result)
	if !ok {
		t.Fatalf("result is not an object: %s", result)
	}
	if resultType != ResultTypeTask || status != TaskStatusWorking {
		t.Fatalf("resultType/status = %q/%q", resultType, status)
	}
	if handle == upstreamTaskCallID || handle == "" {
		t.Fatalf("taskId = %q, want a minted handle", handle)
	}
	var envelope struct {
		PollIntervalMs int64 `json:"pollIntervalMs"`
		TTLMs          int64 `json:"ttlMs"`
	}
	if err := json.Unmarshal(result, &envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if envelope.PollIntervalMs != taskPollFloorMs {
		t.Fatalf("pollIntervalMs = %d, want %d", envelope.PollIntervalMs, taskPollFloorMs)
	}
	if envelope.TTLMs != 600000 {
		t.Fatalf("ttlMs = %d, want the upstream value preserved", envelope.TTLMs)
	}
	if up.callCount != 1 {
		t.Fatalf("upstream calls = %d, want 1", up.callCount)
	}
}

// With no task secret the gateway cannot mediate, so a client must never be
// handed a task id it has no way to poll.
func TestComposer_CallTool_StripsTaskWhenDisabled(t *testing.T) {
	t.Parallel()
	_, dialer, reg, consumer := taskFixture(t)
	c := newTaskComposer(dialer, NewTaskHandleSigner("", "", 0, 0))

	result, err := c.CallTool(context.Background(), routable(consumer, reg), ToolCall{Name: "find"})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	resultType, _, taskID, ok := TaskResultFields(result)
	if !ok {
		t.Fatalf("result is not an object: %s", result)
	}
	if resultType != "complete" || taskID != "" {
		t.Fatalf("resultType/taskId = %q/%q, want complete with no task id", resultType, taskID)
	}
}

// Polling carries the real upstream task id southbound and echoes the inbound
// handle northbound, so a handle stays stable for the task's whole life. It also
// reaches only the registry the handle names, never a sibling.
func TestComposer_GetTask_EchoesHandleAndRoutesUpstreamID(t *testing.T) {
	t.Parallel()
	up, dialer, reg, consumer := taskFixture(t)
	sibling := mcpRegistry(t, "gitlab", "https://b.example.com/mcp")
	dialer.upstreams["https://b.example.com/mcp"] = &taskUpstream{
		fakeUpstream: &fakeUpstream{tools: tools("search")},
		taskResult:   json.RawMessage(workingTaskResult),
	}
	signer := taskTestSigner()
	c := newTaskComposer(dialer, signer)
	rc := routable(consumer, reg, sibling)
	handle := mintHandle(t, signer, taskClaimsFor(rc, reg))

	result, err := c.GetTask(context.Background(), rc, handle)
	if err != nil {
		t.Fatalf("get task: %v", err)
	}
	ref, _, calls := up.observed()
	if ref.TaskID != upstreamTaskCallID {
		t.Fatalf("upstream taskId = %q, want %q", ref.TaskID, upstreamTaskCallID)
	}
	if ref.Exposed != "find" || ref.Upstream != "search" {
		t.Fatalf("ref = %+v, want the exposed/upstream pair the handle bound", ref)
	}
	if _, _, got, _ := TaskResultFields(result); got != handle {
		t.Fatalf("northbound taskId = %q, want the inbound handle", got)
	}
	// Discovery may dial the sibling to compose the surface, but the task itself
	// must be served only by the registry its handle bound.
	if calls != 1 {
		t.Fatalf("task calls on the bound upstream = %d, want 1", calls)
	}
	sib, _ := dialer.upstreams["https://b.example.com/mcp"].(*taskUpstream)
	if _, _, sibCalls := sib.observed(); sibCalls != 0 {
		t.Fatal("a task must never be served by a sibling registry")
	}
}

// tasks/update forwards the client's answers to the upstream task.
func TestComposer_UpdateTask_ForwardsInputResponses(t *testing.T) {
	t.Parallel()
	up, dialer, reg, consumer := taskFixture(t)
	signer := taskTestSigner()
	c := newTaskComposer(dialer, signer)
	rc := routable(consumer, reg)
	handle := mintHandle(t, signer, taskClaimsFor(rc, reg))
	inputs := json.RawMessage(`{"req-1":{"content":{}}}`)

	if _, err := c.UpdateTask(context.Background(), rc, handle, inputs); err != nil {
		t.Fatalf("update task: %v", err)
	}
	if _, forwarded, _ := up.observed(); string(forwarded) != string(inputs) {
		t.Fatalf("inputResponses = %s, want %s", forwarded, inputs)
	}
}

// A cancel acknowledgement carries no task id, so there is nothing to rewrite
// and the ack must pass through untouched.
func TestComposer_CancelTask_PassesThroughAck(t *testing.T) {
	t.Parallel()
	up, dialer, reg, consumer := taskFixture(t)
	up.taskResult = json.RawMessage(`{}`)
	signer := taskTestSigner()
	c := newTaskComposer(dialer, signer)
	rc := routable(consumer, reg)
	handle := mintHandle(t, signer, taskClaimsFor(rc, reg))

	result, err := c.CancelTask(context.Background(), rc, handle)
	if err != nil {
		t.Fatalf("cancel task: %v", err)
	}
	if string(result) != `{}` {
		t.Fatalf("ack = %s, want an untouched empty object", result)
	}
}

// An upstream that predates the extension cannot serve tasks/*, and saying so
// must be indistinguishable from any other refusal.
func TestComposer_GetTask_NonTaskUpstreamRejected(t *testing.T) {
	t.Parallel()
	_, _, reg, consumer := taskFixture(t)
	dialer := newTaskDialer()
	dialer.upstreams["https://a.example.com/mcp"] = &fakeUpstream{tools: tools("search")}
	signer := taskTestSigner()
	c := newTaskComposer(dialer, signer)
	rc := routable(consumer, reg)

	_, err := c.GetTask(context.Background(), rc, mintHandle(t, signer, taskClaimsFor(rc, reg)))
	if got := rpcCode(t, MapTaskError(err)); got != CodeTaskHandleRejected {
		t.Fatalf("code = %d, want %d", got, CodeTaskHandleRejected)
	}
}

// Every re-authorization failure must answer with one identical error and must
// never reach an upstream: the handle cannot become an existence oracle.
func TestComposer_TaskReauthorizationMatrix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		handle func(t *testing.T, signer *TaskHandleSigner, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) string
	}{
		{
			name: "another consumer",
			handle: func(t *testing.T, signer *TaskHandleSigner, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) string {
				claims := taskClaimsFor(rc, reg)
				claims.CID = ids.New[ids.ConsumerKind]().String()
				return mintHandle(t, signer, claims)
			},
		},
		{
			name: "detached registry",
			handle: func(t *testing.T, signer *TaskHandleSigner, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) string {
				claims := taskClaimsFor(rc, reg)
				claims.RID = ids.New[ids.RegistryKind]().String()
				return mintHandle(t, signer, claims)
			},
		},
		{
			name: "toolkit no longer maps the exposed name",
			handle: func(t *testing.T, signer *TaskHandleSigner, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) string {
				claims := taskClaimsFor(rc, reg)
				claims.Exposed = "renamed"
				return mintHandle(t, signer, claims)
			},
		},
		{
			name: "toolkit no longer maps the upstream tool",
			handle: func(t *testing.T, signer *TaskHandleSigner, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) string {
				claims := taskClaimsFor(rc, reg)
				claims.Upstream = "other"
				return mintHandle(t, signer, claims)
			},
		},
		{
			name: "another principal",
			handle: func(t *testing.T, signer *TaskHandleSigner, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) string {
				claims := taskClaimsFor(rc, reg)
				claims.Sub = "0000000000000000000000000000000000000000000000000000000000000000"
				return mintHandle(t, signer, claims)
			},
		},
		{
			name: "tampered handle",
			handle: func(t *testing.T, signer *TaskHandleSigner, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) string {
				return mintHandle(t, signer, taskClaimsFor(rc, reg)) + "x"
			},
		},
		{
			name: "handle minted with an unrelated secret",
			handle: func(t *testing.T, signer *TaskHandleSigner, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) string {
				return mintHandle(t, NewTaskHandleSigner("other-secret", "", 0, 0), taskClaimsFor(rc, reg))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			up, dialer, reg, consumer := taskFixture(t)
			signer := taskTestSigner()
			c := newTaskComposer(dialer, signer)
			rc := routable(consumer, reg)

			_, err := c.GetTask(context.Background(), rc, tt.handle(t, signer, rc, reg))
			rpcErr := mappedTaskError(t, err)
			if rpcErr.Code != CodeTaskHandleRejected {
				t.Fatalf("code = %d, want %d", rpcErr.Code, CodeTaskHandleRejected)
			}
			if rpcErr.Message != TaskHandleRejectedMessage {
				t.Fatalf("message = %q, want the one constant message", rpcErr.Message)
			}
			if rpcErr.Data != nil {
				t.Fatalf("data = %s, want nil so nothing can be inferred", rpcErr.Data)
			}
			if _, _, calls := up.observed(); calls != 0 {
				t.Fatal("a rejected handle must never reach the upstream")
			}
		})
	}
}

func mappedTaskError(t *testing.T, err error) *RPCError {
	t.Helper()
	mapped := MapTaskError(err)
	var rpcErr *RPCError
	if !errors.As(mapped, &rpcErr) {
		t.Fatalf("error = %v, want *RPCError", mapped)
	}
	return rpcErr
}

// taskClaimsFor is the claim set a real mint would produce for this consumer,
// registry, and toolkit entry.
func taskClaimsFor(rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) TaskHandleClaims {
	return TaskHandleClaims{
		GID:      rc.Consumer.GatewayID.String(),
		CID:      rc.Consumer.ID.String(),
		RID:      reg.ID.String(),
		Exposed:  "find",
		Upstream: "search",
		TaskID:   upstreamTaskCallID,
		Created:  time.Now().Unix(),
	}
}
