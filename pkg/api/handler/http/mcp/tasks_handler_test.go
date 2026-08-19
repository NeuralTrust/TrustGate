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
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	approle "github.com/NeuralTrust/TrustGate/pkg/app/role"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const (
	tasksClientMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientCapabilities":` +
		`{"extensions":{"io.modelcontextprotocol/tasks":{}}}}`
	plainClientMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientCapabilities":{}}`
	testTaskHandle = "tg1k.c.handle"
)

type taskOutcomeRecord struct {
	operation string
	outcome   string
	era       string
}

type fakeTasksRecorder struct {
	mu      sync.Mutex
	records []taskOutcomeRecord
}

func (r *fakeTasksRecorder) Record(_ context.Context, operation, outcome, era string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, taskOutcomeRecord{operation: operation, outcome: outcome, era: era})
}

func (r *fakeTasksRecorder) all() []taskOutcomeRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]taskOutcomeRecord(nil), r.records...)
}

// newTasksApp wires a modern MCP consumer with task mediation configurable, so a
// test can prove both the enabled and the fail-closed behaviour.
func newTasksApp(
	t *testing.T,
	composer appmcp.Composer,
	signer *appmcp.TaskHandleSigner,
	recorder mcphttp.TasksRecorder,
) *fiber.App {
	t.Helper()
	return newTasksAppWithRunner(t, composer, noopRunner(), signer, recorder)
}

func newTasksAppWithRunner(
	t *testing.T,
	composer appmcp.Composer,
	plugins *appmcp.PluginRunner,
	signer *appmcp.TaskHandleSigner,
	recorder mcphttp.TasksRecorder,
) *fiber.App {
	t.Helper()
	authID := ids.New[ids.AuthKind]()
	gwID := ids.New[ids.GatewayKind]()
	cons := &consumerdomain.Consumer{
		ID:        ids.New[ids.ConsumerKind](),
		GatewayID: gwID,
		Name:      "virtual",
		Type:      consumerdomain.TypeMCP,
		Slug:      "virtual",
		Active:    true,
		AuthIDs:   []ids.AuthID{authID},
	}
	registries := []*registrydomain.Registry{modernMCPRegistry(t, gwID)}
	data := appconsumer.NewData(gwID, []appconsumer.RoutableConsumer{
		{Consumer: cons, Registries: registries},
	})

	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		ctx := appconsumer.WithAuthID(c.UserContext(), authID)
		ctx = appconsumer.WithData(ctx, data)
		ctx = trace.NewContext(ctx, trace.New("t-tasks", trace.Metadata{Kind: events.KindMCP}))
		c.SetUserContext(ctx)
		return c.Next()
	})
	handler := mcphttp.NewHandlerWithMediation(
		mcphttp.NewRPCGateway(composer, plugins, nil),
		appmcp.NewRoleScoper(approle.NewOIDCResolver()),
		mcphttp.MRTRSupport{},
		mcphttp.TasksSupport{Signer: signer, Recorder: recorder},
	)
	app.Post(mcpPath, handler.Handle)
	return app
}

func taskSigner() *appmcp.TaskHandleSigner {
	return appmcp.NewTaskHandleSigner("task-secret", "", 0, 0)
}

func taskHeaders(method, handle string) http.Header {
	return modernHeadersWithName(method, handle)
}

func taskRequest(method, handle, meta string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{"taskId":"` + handle + `",` + meta + `}}`
}

func rpcErrorObject(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	err, ok := body["error"].(map[string]any)
	require.True(t, ok, "response has no error object: %v", body)
	return err
}

// tasks/* are routable methods on the modern surface: they must not answer
// method-not-found, which is what the gateway did before mediation existed.
func TestHandler_Tasks_MethodsAreRoutable(t *testing.T) {
	t.Parallel()
	for _, method := range []string{"tasks/get", "tasks/update", "tasks/cancel"} {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			composer := mocks.NewComposer(t)
			composer.EXPECT().
				UnwrapTaskHandle(mock.Anything, mock.Anything, testTaskHandle).
				Return(appmcp.TaskRef{Exposed: "find", Upstream: "search"}, nil)
			switch method {
			case "tasks/get":
				composer.EXPECT().GetTask(mock.Anything, mock.Anything, testTaskHandle).
					Return(json.RawMessage(`{"taskId":"`+testTaskHandle+`","status":"working"}`), nil)
			case "tasks/update":
				composer.EXPECT().UpdateTask(mock.Anything, mock.Anything, testTaskHandle, mock.Anything).
					Return(json.RawMessage(`{"taskId":"`+testTaskHandle+`","status":"working"}`), nil)
			case "tasks/cancel":
				composer.EXPECT().CancelTask(mock.Anything, mock.Anything, testTaskHandle).
					Return(json.RawMessage(`{"taskId":"`+testTaskHandle+`","status":"cancelled"}`), nil)
			}

			status, body := rpcCallWithHeaders(t, newTasksApp(t, composer, taskSigner(), nil),
				taskRequest(method, testTaskHandle, tasksClientMeta),
				taskHeaders(method, testTaskHandle))

			require.Equal(t, fiber.StatusOK, status)
			require.Nil(t, body["error"])
			result := mrtrResult(t, body)
			require.Equal(t, "complete", result["resultType"])
			require.Equal(t, float64(0), result["ttlMs"])
			require.Equal(t, "private", result["cacheScope"])
		})
	}
}

// A client that never declared the extension could not hold a handle, so the
// refusal names the missing capability instead of touching a composer.
func TestHandler_Tasks_NonDeclaringClientRejected(t *testing.T) {
	t.Parallel()
	recorder := &fakeTasksRecorder{}
	app := newTasksApp(t, mocks.NewComposer(t), taskSigner(), recorder)

	status, body := rpcCallWithHeaders(t, app,
		taskRequest("tasks/get", testTaskHandle, plainClientMeta),
		taskHeaders("tasks/get", testTaskHandle))

	require.Equal(t, fiber.StatusOK, status)
	rpcErr := rpcErrorObject(t, body)
	require.Equal(t, float64(-32025), rpcErr["code"])
	data, ok := rpcErr["data"].(map[string]any)
	require.True(t, ok, "error carries no data: %v", rpcErr)
	require.Equal(t, []any{"io.modelcontextprotocol/tasks"}, data["requiredCapabilities"])
	require.Equal(t, []taskOutcomeRecord{
		{operation: "get", outcome: "capability_required", era: "modern"},
	}, recorder.all())
}

// With no task secret the declaration is dropped at the single choke point, so a
// client that declared the extension still cannot reach tasks/*.
func TestHandler_Tasks_FailClosedWithoutSecret(t *testing.T) {
	t.Parallel()
	app := newTasksApp(t, mocks.NewComposer(t), appmcp.NewTaskHandleSigner("", "", 0, 0), nil)

	status, body := rpcCallWithHeaders(t, app,
		taskRequest("tasks/get", testTaskHandle, tasksClientMeta),
		taskHeaders("tasks/get", testTaskHandle))

	require.Equal(t, fiber.StatusOK, status)
	require.Equal(t, float64(-32025), rpcErrorObject(t, body)["code"])
}

// The Mcp-Name header must agree with params.taskId, exactly as it must for a
// tool name: a mismatch is a protocol failure, not a handle failure.
func TestHandler_Tasks_NameHeaderMismatch(t *testing.T) {
	t.Parallel()
	app := newTasksApp(t, mocks.NewComposer(t), taskSigner(), nil)

	status, body := rpcCallWithHeaders(t, app,
		taskRequest("tasks/get", testTaskHandle, tasksClientMeta),
		taskHeaders("tasks/get", "another-handle"))

	require.Equal(t, fiber.StatusBadRequest, status)
	require.Equal(t, float64(-32020), rpcErrorObject(t, body)["code"])
}

// An oversize handle is refused before any verification work, with the same
// constant message every other handle refusal carries.
func TestHandler_Tasks_OversizeHandleRejected(t *testing.T) {
	t.Parallel()
	handle := strings.Repeat("h", 2049)
	app := newTasksApp(t, mocks.NewComposer(t), taskSigner(), nil)

	status, body := rpcCallWithHeaders(t, app,
		taskRequest("tasks/get", handle, tasksClientMeta),
		taskHeaders("tasks/get", handle))

	require.Equal(t, fiber.StatusBadRequest, status)
	rpcErr := rpcErrorObject(t, body)
	require.Equal(t, float64(-32602), rpcErr["code"])
	require.Equal(t, appmcp.TaskHandleRejectedMessage, rpcErr["message"])
	require.Nil(t, rpcErr["data"])
}

// A rejected handle answers one indistinguishable error and records only that it
// was rejected, so telemetry cannot become an oracle either.
func TestHandler_Tasks_RejectedHandleIsOpaque(t *testing.T) {
	t.Parallel()
	recorder := &fakeTasksRecorder{}
	composer := mocks.NewComposer(t)
	composer.EXPECT().
		UnwrapTaskHandle(mock.Anything, mock.Anything, testTaskHandle).
		Return(appmcp.TaskRef{}, appmcp.ErrTaskHandleRejected)
	app := newTasksApp(t, composer, taskSigner(), recorder)

	// An app-level JSON-RPC error answers HTTP 200 so the client parses the
	// error instead of tearing down the transport.
	status, body := rpcCallWithHeaders(t, app,
		taskRequest("tasks/get", testTaskHandle, tasksClientMeta),
		taskHeaders("tasks/get", testTaskHandle))

	require.Equal(t, fiber.StatusOK, status)
	rpcErr := rpcErrorObject(t, body)
	require.Equal(t, float64(-32602), rpcErr["code"])
	require.Equal(t, appmcp.TaskHandleRejectedMessage, rpcErr["message"])
	require.Nil(t, rpcErr["data"])
	require.Equal(t, []taskOutcomeRecord{
		{operation: "get", outcome: "handle_rejected", era: "modern"},
	}, recorder.all())
}

// The extension is advertised only when TrustGate can actually mediate: a secret
// must be configured and a modern registry must be bound.
func TestHandler_ServerDiscover_TasksAdvertisement(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		signer    *appmcp.TaskHandleSigner
		advertise bool
	}{
		{name: "secret configured", signer: taskSigner(), advertise: true},
		{name: "secret missing", signer: appmcp.NewTaskHandleSigner("", "", 0, 0), advertise: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			app := newTasksApp(t, mocks.NewComposer(t), tc.signer, nil)
			status, body := rpcCallWithHeaders(t, app,
				`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{`+tasksClientMeta+`}}`,
				modernHeadersFor("server/discover"))

			require.Equal(t, fiber.StatusOK, status)
			capabilities, ok := mrtrResult(t, body)["capabilities"].(map[string]any)
			require.True(t, ok)
			if !tc.advertise {
				require.NotContains(t, capabilities, "extensions")
				return
			}
			require.Equal(t, map[string]any{
				"io.modelcontextprotocol/tasks": map[string]any{},
			}, capabilities["extensions"])
		})
	}
}

// A legacy initialize must not learn about the extension: the tasks contract is
// modern-only.
func TestHandler_LegacyInitialize_NeverAdvertisesTasks(t *testing.T) {
	t.Parallel()
	app := newTasksApp(t, mocks.NewComposer(t), taskSigner(), nil)

	status, body := rpcCall(t, app,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)

	require.Equal(t, fiber.StatusOK, status)
	capabilities, ok := mrtrResult(t, body)["capabilities"].(map[string]any)
	require.True(t, ok)
	require.NotContains(t, capabilities, "extensions")
}

// The tool output a completed task carries must take the response stage under
// the tool's exposed name. Before this, long-running output was delivered by
// tasks/get having never been scanned: the tools/call that started the task
// returned only a task envelope, so TrustGuard saw nothing to inspect.
func TestHandler_TasksGet_TerminalResultTakesResponseStage(t *testing.T) {
	t.Parallel()
	terminal := `{"taskId":"` + testTaskHandle + `","status":"completed",` +
		`"result":{"content":[{"type":"text","text":"secret"}]}}`
	composer := mocks.NewComposer(t)
	composer.EXPECT().
		UnwrapTaskHandle(mock.Anything, mock.Anything, testTaskHandle).
		Return(appmcp.TaskRef{Exposed: "find", Upstream: "search"}, nil)
	composer.EXPECT().GetTask(mock.Anything, mock.Anything, testTaskHandle).
		Return(json.RawMessage(terminal), nil)

	exec := pluginmocks.NewExecutor(t)
	var captured appplugins.StageInput
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).
		Run(func(_ context.Context, in appplugins.StageInput) { captured = in }).
		Return(&appplugins.StageOutcome{}, nil)

	app := newTasksAppWithRunner(t, composer, appmcp.NewPluginRunner(exec, discardLogger()), taskSigner(), nil)
	status, body := rpcCallWithHeaders(t, app,
		taskRequest("tasks/get", testTaskHandle, tasksClientMeta),
		taskHeaders("tasks/get", testTaskHandle))

	require.Equal(t, fiber.StatusOK, status)
	require.Nil(t, body["error"])
	require.Equal(t, policydomain.StagePreResponse, captured.Stage)
	require.NotNil(t, captured.Request)
	require.Contains(t, string(captured.Request.Body), `"find"`,
		"the stage must run under the exposed tool name the handle recovered")
	require.NotNil(t, captured.Response)
	require.JSONEq(t, `{"content":[{"type":"text","text":"secret"}]}`, string(captured.Response.Body),
		"the stage must see the tool output the task carries, not the task envelope")
}

// A denial on the terminal result withholds the tool content: the client gets the
// policy error, never the payload.
func TestHandler_TasksGet_DeniedTerminalResultWithholdsContent(t *testing.T) {
	t.Parallel()
	terminal := `{"taskId":"` + testTaskHandle + `","status":"completed",` +
		`"result":{"content":[{"type":"text","text":"secret"}]}}`
	recorder := &fakeTasksRecorder{}
	composer := mocks.NewComposer(t)
	composer.EXPECT().
		UnwrapTaskHandle(mock.Anything, mock.Anything, testTaskHandle).
		Return(appmcp.TaskRef{Exposed: "find", Upstream: "search"}, nil)
	composer.EXPECT().GetTask(mock.Anything, mock.Anything, testTaskHandle).
		Return(json.RawMessage(terminal), nil)

	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).
		Return(nil, &appplugins.PluginError{StatusCode: 403, Message: "blocked", Body: []byte(`{"trace_id":"t1"}`)})

	app := newTasksAppWithRunner(t, composer, appmcp.NewPluginRunner(exec, discardLogger()), taskSigner(), recorder)
	status, raw := rpcRawCallWithHeaders(t, app,
		taskRequest("tasks/get", testTaskHandle, tasksClientMeta),
		taskHeaders("tasks/get", testTaskHandle))

	require.Equal(t, fiber.StatusOK, status)
	require.NotContains(t, string(raw), "secret")
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body))
	require.Equal(t, float64(-32001), rpcErrorObject(t, body)["code"])
	require.Equal(t, []taskOutcomeRecord{
		{operation: "get", outcome: "policy_denied", era: "modern"},
	}, recorder.all())
}

// A 2xx rewrite is a masked payload, not a denial: it is spliced back into the
// task envelope so the client still gets a well-formed task result.
func TestHandler_TasksGet_RewrittenTerminalResultIsSpliced(t *testing.T) {
	t.Parallel()
	terminal := `{"taskId":"` + testTaskHandle + `","status":"completed",` +
		`"result":{"content":[{"type":"text","text":"secret"}]}}`
	composer := mocks.NewComposer(t)
	composer.EXPECT().
		UnwrapTaskHandle(mock.Anything, mock.Anything, testTaskHandle).
		Return(appmcp.TaskRef{Exposed: "find", Upstream: "search"}, nil)
	composer.EXPECT().GetTask(mock.Anything, mock.Anything, testTaskHandle).
		Return(json.RawMessage(terminal), nil)

	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).Return(&appplugins.StageOutcome{
		ShortCircuit: true,
		StatusCode:   200,
		Body:         []byte(`{"content":[{"type":"text","text":"[REDACTED]"}]}`),
	}, nil)

	app := newTasksAppWithRunner(t, composer, appmcp.NewPluginRunner(exec, discardLogger()), taskSigner(), nil)
	status, body := rpcCallWithHeaders(t, app,
		taskRequest("tasks/get", testTaskHandle, tasksClientMeta),
		taskHeaders("tasks/get", testTaskHandle))

	require.Equal(t, fiber.StatusOK, status)
	result := mrtrResult(t, body)
	require.Equal(t, "completed", result["status"])
	inner, ok := result["result"].(map[string]any)
	require.True(t, ok, "the task envelope must survive the rewrite: %v", result)
	require.Contains(t, mustJSON(t, inner), "[REDACTED]")
	require.NotContains(t, mustJSON(t, inner), "secret")
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	return string(encoded)
}
