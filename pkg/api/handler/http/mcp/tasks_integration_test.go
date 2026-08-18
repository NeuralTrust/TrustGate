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

package mcp_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
)

// scriptedTaskUpstream is a modern upstream that answers tools/call with a task
// and then serves that task through the extension, so the whole lifecycle can be
// driven through the real handler, dispatcher, and composer.
type scriptedTaskUpstream struct {
	*fakeMRTRUpstream

	mu        sync.Mutex
	status    string
	getCalls  int
	cancelled bool
	lastRef   appmcp.TaskRef
}

func newScriptedTaskUpstream() *scriptedTaskUpstream {
	return &scriptedTaskUpstream{
		fakeMRTRUpstream: &fakeMRTRUpstream{results: []string{
			`{"resultType":"task","taskId":"u-123","status":"working",` +
				`"createdAt":"2026-01-01T00:00:00Z","ttlMs":600000,"pollIntervalMs":10}`,
		}},
		status: "working",
	}
}

func (u *scriptedTaskUpstream) complete() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.status = "completed"
}

func (u *scriptedTaskUpstream) GetTask(_ context.Context, ref appmcp.TaskRef) (json.RawMessage, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.getCalls++
	u.lastRef = ref
	if u.status == "completed" {
		return json.RawMessage(`{"taskId":"u-123","status":"completed",` +
			`"result":{"content":[{"type":"text","text":"done"}]}}`), nil
	}
	return json.RawMessage(`{"taskId":"u-123","status":"working","pollIntervalMs":10}`), nil
}

func (u *scriptedTaskUpstream) UpdateTask(
	_ context.Context,
	ref appmcp.TaskRef,
	_ json.RawMessage,
) (json.RawMessage, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.lastRef = ref
	return json.RawMessage(`{"taskId":"u-123","status":"working"}`), nil
}

func (u *scriptedTaskUpstream) CancelTask(_ context.Context, ref appmcp.TaskRef) (json.RawMessage, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.cancelled = true
	u.lastRef = ref
	return json.RawMessage(`{"taskId":"u-123","status":"cancelled"}`), nil
}

func (u *scriptedTaskUpstream) snapshot() (getCalls int, cancelled bool, ref appmcp.TaskRef) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.getCalls, u.cancelled, u.lastRef
}

type scriptedTaskDialer struct{ upstream appmcp.Upstream }

func (d *scriptedTaskDialer) Connect(context.Context, appmcp.Target) (appmcp.Upstream, error) {
	return d.upstream, nil
}

func taskComposerFor(t *testing.T, up appmcp.Upstream, signer *appmcp.TaskHandleSigner) appmcp.Composer {
	t.Helper()
	return appmcp.NewComposerWithMediation(
		&scriptedTaskDialer{upstream: up},
		nil,
		&mrtrMapCache{m: map[string]any{}},
		discardLogger(),
		nil,
		signer,
		1000,
	)
}

func taskToolCall(t *testing.T, app *fiber.App) map[string]any {
	t.Helper()
	status, body := rpcCallWithHeaders(t, app,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search",`+tasksClientMeta+`}}`,
		modernHeadersWithName("tools/call", "search"))
	require.Equal(t, fiber.StatusOK, status)
	require.Nil(t, body["error"])
	return mrtrResult(t, body)
}

// The whole lifecycle over the real stack: a tools/call that creates a task, two
// polls across the transition to completed, and a cancel — all addressed by the
// handle the gateway minted, with the upstream only ever seeing its own task id.
func TestTasksLifecycle_CreatePollTerminalCancel(t *testing.T) {
	t.Parallel()
	upstream := newScriptedTaskUpstream()
	signer := appmcp.NewTaskHandleSigner("task-secret", "", 0, 0)
	app := newTasksApp(t, taskComposerFor(t, upstream, signer), signer, nil)

	created := taskToolCall(t, app)
	require.Equal(t, "task", created["resultType"])
	handle, ok := created["taskId"].(string)
	require.True(t, ok)
	require.NotEqual(t, "u-123", handle, "the upstream task id must never reach the client")
	require.Equal(t, float64(1000), created["pollIntervalMs"],
		"the upstream's 10ms poll interval must be clamped to the configured floor")
	require.Equal(t, float64(600000), created["ttlMs"])

	working := taskPoll(t, app, handle)
	require.Equal(t, "working", working["status"])
	require.Equal(t, handle, working["taskId"], "the handle must be stable across polls")
	require.Equal(t, "complete", working["resultType"])

	upstream.complete()
	terminal := taskPoll(t, app, handle)
	require.Equal(t, "completed", terminal["status"])
	require.Equal(t, handle, terminal["taskId"])
	inner, ok := terminal["result"].(map[string]any)
	require.True(t, ok, "a completed task must carry the tool result: %v", terminal)
	require.Contains(t, mustJSON(t, inner), "done")

	status, body := rpcCallWithHeaders(t, app,
		taskRequest("tasks/cancel", handle, tasksClientMeta),
		taskHeaders("tasks/cancel", handle))
	require.Equal(t, fiber.StatusOK, status)
	require.Equal(t, "cancelled", mrtrResult(t, body)["status"])

	getCalls, cancelled, ref := upstream.snapshot()
	require.Equal(t, 2, getCalls)
	require.True(t, cancelled)
	require.Equal(t, "u-123", ref.TaskID, "the upstream must be addressed by its own task id")
	require.Equal(t, "search", ref.Upstream)
}

func taskPoll(t *testing.T, app *fiber.App, handle string) map[string]any {
	t.Helper()
	status, body := rpcCallWithHeaders(t, app,
		taskRequest("tasks/get", handle, tasksClientMeta),
		taskHeaders("tasks/get", handle))
	require.Equal(t, fiber.StatusOK, status)
	require.Nil(t, body["error"])
	return mrtrResult(t, body)
}

// Unsetting the secret is the rollback lever: the gateway stops mediating, and a
// task-shaped upstream answer degrades to an ordinary complete result rather than
// handing the client a task id it cannot poll.
func TestTasksLifecycle_SecretUnsetRestoresPreChangeBehaviour(t *testing.T) {
	t.Parallel()
	upstream := newScriptedTaskUpstream()
	signer := appmcp.NewTaskHandleSigner("", "", 0, 0)
	app := newTasksApp(t, taskComposerFor(t, upstream, signer), signer, nil)

	created := taskToolCall(t, app)
	require.Equal(t, "complete", created["resultType"])
	require.NotContains(t, created, "taskId")
	require.NotContains(t, created, "status")

	status, body := rpcCallWithHeaders(t, app,
		taskRequest("tasks/get", "tg1k.c.whatever", tasksClientMeta),
		taskHeaders("tasks/get", "tg1k.c.whatever"))
	require.Equal(t, fiber.StatusOK, status)
	require.Equal(t, float64(-32025), rpcErrorObject(t, body)["code"])

	getCalls, cancelled, _ := upstream.snapshot()
	require.Zero(t, getCalls)
	require.False(t, cancelled)
}
