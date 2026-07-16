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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	ratelimitmocks "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit/mocks"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestRPCGateway_ToolsList_DefaultsToEmptySlice(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return(nil, nil).Once()

	g := mcphttp.NewRPCGateway(composer, noopRunner(), nil)
	res, err := g.Dispatch(context.Background(), &appconsumer.RoutableConsumer{}, "tools/list", nil)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	body, _ := json.Marshal(res)
	if string(body) != `{"tools":[]}` {
		t.Fatalf("tools/list = %s, want empty array (clients reject null)", body)
	}
}

func TestRPCGateway_ToolsCall_RequiresName(t *testing.T) {
	t.Parallel()
	g := mcphttp.NewRPCGateway(mocks.NewComposer(t), noopRunner(), nil)
	_, err := g.Dispatch(context.Background(), &appconsumer.RoutableConsumer{}, "tools/call", json.RawMessage(`{}`))
	var invalid *mcphttp.InvalidParamsError
	if !errors.As(err, &invalid) {
		t.Fatalf("error = %v, want mcphttp.InvalidParamsError", err)
	}
}

func TestRPCGateway_ToolsCall_ForwardsRawResult(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)
	composer := mocks.NewComposer(t)
	composer.EXPECT().
		CallTool(mock.Anything, mock.Anything, "echo", mock.Anything).
		Return(raw, nil).Once()

	g := mcphttp.NewRPCGateway(composer, noopRunner(), nil)
	res, err := g.Dispatch(context.Background(), &appconsumer.RoutableConsumer{}, "tools/call", json.RawMessage(`{"name":"echo"}`))
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	got, ok := res.(json.RawMessage)
	if !ok || string(got) != string(raw) {
		t.Fatalf("result = %#v, want verbatim raw payload", res)
	}
}

func TestRPCGateway_ResourcesRead_RequiresURI(t *testing.T) {
	t.Parallel()
	g := mcphttp.NewRPCGateway(mocks.NewComposer(t), noopRunner(), nil)
	_, err := g.Dispatch(context.Background(), &appconsumer.RoutableConsumer{}, "resources/read", json.RawMessage(`{}`))
	var invalid *mcphttp.InvalidParamsError
	if !errors.As(err, &invalid) {
		t.Fatalf("error = %v, want mcphttp.InvalidParamsError", err)
	}
}

func TestRPCGateway_UnknownMethod(t *testing.T) {
	t.Parallel()
	g := mcphttp.NewRPCGateway(mocks.NewComposer(t), noopRunner(), nil)
	_, err := g.Dispatch(context.Background(), &appconsumer.RoutableConsumer{}, "tools/subscribe", nil)
	if !errors.Is(err, mcphttp.ErrMethodNotFound) {
		t.Fatalf("error = %v, want mcphttp.ErrMethodNotFound", err)
	}
}

func TestRPCGateway_PromptsGet_RequiresName(t *testing.T) {
	t.Parallel()
	g := mcphttp.NewRPCGateway(mocks.NewComposer(t), noopRunner(), nil)
	_, err := g.Dispatch(context.Background(), &appconsumer.RoutableConsumer{}, "prompts/get", json.RawMessage(`{"arguments":{}}`))
	var invalid *mcphttp.InvalidParamsError
	if !errors.As(err, &invalid) {
		t.Fatalf("error = %v, want mcphttp.InvalidParamsError", err)
	}
}

func mcpRoutableConsumer() *appconsumer.RoutableConsumer {
	return &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{Type: consumerdomain.TypeMCP},
	}
}

func blockErr(traceID string) *appplugins.PluginError {
	return &appplugins.PluginError{
		StatusCode: 403,
		Message:    "request blocked due to a policy infraction",
		Body:       []byte(`{"trace_id":"` + traceID + `"}`),
	}
}

func TestRPCGateway_ToolsCall_PreRequestBlock_SkipsUpstream(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).Return(nil, blockErr("pre")).Once()

	g := mcphttp.NewRPCGateway(composer, appmcp.NewPluginRunner(exec, discardLogger()), nil)
	res, err := g.Dispatch(
		context.Background(),
		mcpRoutableConsumer(),
		"tools/call",
		json.RawMessage(`{"name":"echo","arguments":{"q":"x"}}`),
	)

	assert.Nil(t, res)
	var rpcErr *appmcp.RPCError
	require.True(t, errors.As(err, &rpcErr), "want *appmcp.RPCError, got %v", err)
	assert.Equal(t, int64(-32001), rpcErr.Code)
	composer.AssertNotCalled(t, "CallTool", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestRPCGateway_ToolsCall_PreResponseBlock_DiscardsResult(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{"content":[{"type":"text","text":"secret"}]}`)
	composer := mocks.NewComposer(t)
	composer.EXPECT().CallTool(mock.Anything, mock.Anything, "echo", mock.Anything).Return(raw, nil).Once()

	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.MatchedBy(func(in appplugins.StageInput) bool {
		return in.Stage == policydomain.StagePreRequest
	})).Return(&appplugins.StageOutcome{}, nil).Once()
	exec.EXPECT().RunStage(mock.Anything, mock.MatchedBy(func(in appplugins.StageInput) bool {
		return in.Stage == policydomain.StagePreResponse
	})).Return(nil, blockErr("post")).Once()

	g := mcphttp.NewRPCGateway(composer, appmcp.NewPluginRunner(exec, discardLogger()), nil)
	res, err := g.Dispatch(
		context.Background(),
		mcpRoutableConsumer(),
		"tools/call",
		json.RawMessage(`{"name":"echo"}`),
	)

	assert.Nil(t, res)
	var rpcErr *appmcp.RPCError
	require.True(t, errors.As(err, &rpcErr), "want *appmcp.RPCError, got %v", err)
	assert.Equal(t, int64(-32001), rpcErr.Code)
}

func TestRPCGateway_ToolsCall_Allow_ReturnsResultUnchanged(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)
	composer := mocks.NewComposer(t)
	composer.EXPECT().CallTool(mock.Anything, mock.Anything, "echo", mock.Anything).Return(raw, nil).Once()

	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).Return(&appplugins.StageOutcome{}, nil).Twice()

	g := mcphttp.NewRPCGateway(composer, appmcp.NewPluginRunner(exec, discardLogger()), nil)
	res, err := g.Dispatch(
		context.Background(),
		mcpRoutableConsumer(),
		"tools/call",
		json.RawMessage(`{"name":"echo"}`),
	)

	require.NoError(t, err)
	got, ok := res.(json.RawMessage)
	require.True(t, ok, "result = %#v, want json.RawMessage", res)
	assert.Equal(t, string(raw), string(got))
}

func TestHandler_ToolsCall_PreRequestBlock_RendersJSONRPCErrorAt200(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).Return(nil, blockErr("e2e")).Once()

	app := newAppWithRunner(t, composer, appmcp.NewPluginRunner(exec, discardLogger()), consumerdomain.TypeMCP, true)
	status, body := rpcCall(t, app, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"echo"}}`)

	if status != fiber.StatusOK {
		t.Fatalf("JSON-RPC errors must ride on HTTP 200, got %d", status)
	}
	rpcErr := body["error"].(map[string]any)
	if rpcErr["code"].(float64) != -32001 {
		t.Fatalf("code = %v, want -32001 policy blocked", rpcErr["code"])
	}
	composer.AssertNotCalled(t, "CallTool", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestHandler_ToolsCall_RateLimitPropagatesHeaders(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).Return(nil, &appplugins.PluginError{
		StatusCode: 429,
		Message:    "rate limit exceeded",
		Body:       []byte(`{"error":"rate limit exceeded","reason":"quota"}`),
		Headers: map[string][]string{
			"Retry-After":        {"30"},
			"X-RateLimit-Reason": {"quota"},
			"X-RateLimit-Limit":  {"10000"},
		},
	}).Once()

	appFiber := newAppWithRunner(t, composer, appmcp.NewPluginRunner(exec, discardLogger()), consumerdomain.TypeMCP, true)
	req := httptest.NewRequest(http.MethodPost, mcpPath, strings.NewReader(
		`{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"echo"}}`,
	))
	req.Header.Set("Content-Type", "application/json")
	resp, err := appFiber.Test(req, -1)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	require.Equal(t, "30", resp.Header.Get("Retry-After"))
	require.Equal(t, "quota", resp.Header.Get("X-RateLimit-Reason"))
	require.Equal(t, "10000", resp.Header.Get("X-RateLimit-Limit"))

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	rpcErr := body["error"].(map[string]any)
	require.Equal(t, float64(-32004), rpcErr["code"])
	composer.AssertNotCalled(t, "CallTool", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestRPCGateway_ToolsCall_GatewayPlanExceeded_ReturnsRPCErrorWithHeaders(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	limiter := ratelimitmocks.NewChecker(t)
	limiter.EXPECT().Check(mock.Anything, mock.Anything).Return(&ratelimitapp.Exceeded{
		Reason:     ratelimitapp.ReasonBurst,
		Limit:      60,
		Remaining:  0,
		RetryAfter: 5 * time.Second,
	}).Once()

	g := mcphttp.NewRPCGateway(composer, noopRunner(), limiter)
	rc := &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{Type: consumerdomain.TypeMCP, GatewayID: ids.New[ids.GatewayKind]()},
	}
	res, err := g.Dispatch(context.Background(), rc, "tools/call", json.RawMessage(`{"name":"echo"}`))

	assert.Nil(t, res)
	var rpcErr *appmcp.RPCError
	require.True(t, errors.As(err, &rpcErr), "want *appmcp.RPCError, got %v", err)
	assert.Equal(t, appmcp.CodeRateLimited, rpcErr.Code)
	assert.Equal(t, []string{"5"}, rpcErr.HTTPHeaders["Retry-After"])
	assert.Equal(t, []string{"60"}, rpcErr.HTTPHeaders["X-RateLimit-Limit"])
	assert.Equal(t, []string{"0"}, rpcErr.HTTPHeaders["X-RateLimit-Remaining"])
	assert.Equal(t, []string{ratelimitapp.ReasonBurst}, rpcErr.HTTPHeaders["X-RateLimit-Reason"])
	composer.AssertNotCalled(t, "CallTool", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestRPCGateway_ResourcesRead_GatewayPlanExceeded_ReturnsRPCError(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	limiter := ratelimitmocks.NewChecker(t)
	limiter.EXPECT().Check(mock.Anything, mock.Anything).Return(&ratelimitapp.Exceeded{
		Reason:     ratelimitapp.ReasonBurst,
		Limit:      60,
		Remaining:  0,
		RetryAfter: 5 * time.Second,
	}).Once()

	g := mcphttp.NewRPCGateway(composer, noopRunner(), limiter)
	rc := &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{Type: consumerdomain.TypeMCP, GatewayID: ids.New[ids.GatewayKind]()},
	}
	res, err := g.Dispatch(context.Background(), rc, "resources/read", json.RawMessage(`{"uri":"file://x"}`))

	assert.Nil(t, res)
	var rpcErr *appmcp.RPCError
	require.True(t, errors.As(err, &rpcErr), "want *appmcp.RPCError, got %v", err)
	assert.Equal(t, appmcp.CodeRateLimited, rpcErr.Code)
	composer.AssertNotCalled(t, "ReadResource", mock.Anything, mock.Anything, mock.Anything)
}

func TestRPCGateway_PromptsGet_GatewayPlanExceeded_ReturnsRPCError(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	limiter := ratelimitmocks.NewChecker(t)
	limiter.EXPECT().Check(mock.Anything, mock.Anything).Return(&ratelimitapp.Exceeded{
		Reason:     ratelimitapp.ReasonBurst,
		Limit:      60,
		Remaining:  0,
		RetryAfter: 5 * time.Second,
	}).Once()

	g := mcphttp.NewRPCGateway(composer, noopRunner(), limiter)
	rc := &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{Type: consumerdomain.TypeMCP, GatewayID: ids.New[ids.GatewayKind]()},
	}
	res, err := g.Dispatch(context.Background(), rc, "prompts/get", json.RawMessage(`{"name":"greet"}`))

	assert.Nil(t, res)
	var rpcErr *appmcp.RPCError
	require.True(t, errors.As(err, &rpcErr), "want *appmcp.RPCError, got %v", err)
	assert.Equal(t, appmcp.CodeRateLimited, rpcErr.Code)
	composer.AssertNotCalled(t, "GetPrompt", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestRPCGateway_ToolsCall_GatewayPlanUnavailable_PropagatesError(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	limiter := ratelimitmocks.NewChecker(t)
	limiter.EXPECT().Check(mock.Anything, mock.Anything).Return(ratelimitapp.ErrUnavailable).Once()

	g := mcphttp.NewRPCGateway(composer, noopRunner(), limiter)
	rc := &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{Type: consumerdomain.TypeMCP, GatewayID: ids.New[ids.GatewayKind]()},
	}
	res, err := g.Dispatch(context.Background(), rc, "tools/call", json.RawMessage(`{"name":"echo"}`))

	assert.Nil(t, res)
	require.True(t, errors.Is(err, ratelimitapp.ErrUnavailable))
	composer.AssertNotCalled(t, "CallTool", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}
