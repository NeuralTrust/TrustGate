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

func toolCallNamed(name string) any {
	return mock.MatchedBy(func(call appmcp.ToolCall) bool { return call.Name == name })
}

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

func mustRPCJSON[T any](t *testing.T, raw string) T {
	t.Helper()
	var value T
	require.NoError(t, json.Unmarshal([]byte(raw), &value))
	return value
}

func enabledAppsListPolicy(t *testing.T) appmcp.AppsListPolicy {
	t.Helper()
	metadata, err := appmcp.NewAppsMetadataPolicy(2, 2, nil, nil)
	require.NoError(t, err)
	return appmcp.NewAppsListPolicy(true, metadata)
}

func TestRPCGateway_AppsPolicyFiltersListings(t *testing.T) {
	t.Parallel()
	policy := enabledAppsListPolicy(t)
	t.Run("tools before discovery plugin", func(t *testing.T) {
		composer := mocks.NewComposer(t)
		composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return([]appmcp.Tool{
			mustRPCJSON[appmcp.Tool](t, `{"name":"invalid","_meta":{"ui":"bad"}}`),
			mustRPCJSON[appmcp.Tool](t, `{"name":"app","description":"keep","_meta":{"ui":{"resourceUri":"ui://widget/app"}}}`),
			mustRPCJSON[appmcp.Tool](t, `{"name":"plain","_meta":{"trace":1}}`),
		}, nil).Once()
		exec := pluginmocks.NewExecutor(t)
		var discovered []byte
		exec.EXPECT().RunStage(mock.Anything, mock.Anything).
			Run(func(_ context.Context, in appplugins.StageInput) {
				discovered = append([]byte(nil), in.Response.Body...)
			}).Return(&appplugins.StageOutcome{}, nil).Once()
		g := mcphttp.NewRPCGatewayWithAppsListPolicy(
			composer, appmcp.NewPluginRunner(exec, discardLogger()), nil, policy, mcphttp.DefaultMaxContinuationBytes,
		)
		result, err := g.Dispatch(context.Background(), mcpRoutableConsumer(), "tools/list", nil)
		require.NoError(t, err)
		want := `{"tools":[{"name":"app","description":"keep","_meta":{"ui":{"resourceUri":"ui://widget/app"}}},{"name":"plain","_meta":{"trace":1}}]}`
		body, err := json.Marshal(result)
		require.NoError(t, err)
		assert.JSONEq(t, want, string(body))
		assert.JSONEq(t, want, string(discovered))
	})
	t.Run("resources without plugin", func(t *testing.T) {
		composer := mocks.NewComposer(t)
		composer.EXPECT().ListResources(mock.Anything, mock.Anything).Return([]appmcp.Resource{
			mustRPCJSON[appmcp.Resource](t, `{"name":"invalid","uri":"https://example.com","_meta":{"ui":{}}}`),
			mustRPCJSON[appmcp.Resource](t, `{"name":"app","uri":"ui://widget/app","_meta":{"ui":{}}}`),
			mustRPCJSON[appmcp.Resource](t, `{"name":"plain","uri":"https://example.com","_meta":{"trace":1}}`),
		}, nil).Once()
		exec := pluginmocks.NewExecutor(t)
		g := mcphttp.NewRPCGatewayWithAppsListPolicy(
			composer, appmcp.NewPluginRunner(exec, discardLogger()), nil, policy, mcphttp.DefaultMaxContinuationBytes,
		)
		result, err := g.Dispatch(context.Background(), mcpRoutableConsumer(), "resources/list", nil)
		require.NoError(t, err)
		body, err := json.Marshal(result)
		require.NoError(t, err)
		assert.JSONEq(t, `{"resources":[{"name":"app","uri":"ui://widget/app","_meta":{"ui":{}}},{"name":"plain","uri":"https://example.com","_meta":{"trace":1}}]}`, string(body))
		exec.AssertNotCalled(t, "RunStage", mock.Anything, mock.Anything)
	})
}

func TestRPCGateway_AppsPolicyKeepsAllInvalidListNonNull(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return([]appmcp.Tool{
		mustRPCJSON[appmcp.Tool](t, `{"name":"one","_meta":{"ui":"bad"}}`),
		mustRPCJSON[appmcp.Tool](t, `{"name":"two","_meta":{"ui/x":true}}`),
	}, nil).Once()
	g := mcphttp.NewRPCGatewayWithAppsListPolicy(
		composer, noopRunner(), nil, enabledAppsListPolicy(t), mcphttp.DefaultMaxContinuationBytes,
	)
	result, err := g.Dispatch(context.Background(), mcpRoutableConsumer(), "tools/list", nil)
	require.NoError(t, err)
	body, err := json.Marshal(result)
	require.NoError(t, err)
	assert.JSONEq(t, `{"tools":[]}`, string(body))
}

func TestRPCGateway_LegacyConstructorsDisableAppsPolicy(t *testing.T) {
	t.Parallel()
	constructors := map[string]func(appmcp.Composer) *mcphttp.RPCGateway{
		"default": func(composer appmcp.Composer) *mcphttp.RPCGateway {
			return mcphttp.NewRPCGateway(composer, noopRunner(), nil)
		},
		"limits": func(composer appmcp.Composer) *mcphttp.RPCGateway {
			return mcphttp.NewRPCGatewayWithLimits(composer, noopRunner(), nil, 1024)
		},
	}
	for name, construct := range constructors {
		t.Run(name, func(t *testing.T) {
			composer := mocks.NewComposer(t)
			composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return([]appmcp.Tool{
				mustRPCJSON[appmcp.Tool](t, `{"name":"legacy","_meta":{"ui":"bad"}}`),
			}, nil).Once()
			result, err := construct(composer).Dispatch(context.Background(), mcpRoutableConsumer(), "tools/list", nil)
			require.NoError(t, err)
			body, err := json.Marshal(result)
			require.NoError(t, err)
			assert.JSONEq(t, `{"tools":[{"name":"legacy","_meta":{"ui":"bad"}}]}`, string(body))
		})
	}
}

func TestRPCGateway_AppsPolicyFiltersSubscriptionAdmission(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return([]appmcp.Tool{
		mustRPCJSON[appmcp.Tool](t, `{"name":"invalid","_meta":{"ui":"bad"}}`),
		mustRPCJSON[appmcp.Tool](t, `{"name":"visible","_meta":{"ui":{"resourceUri":"ui://widget/visible"}}}`),
	}, nil).Once()
	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.MatchedBy(func(in appplugins.StageInput) bool {
		return in.Response != nil && string(in.Response.Body) == `{"tools":[{"_meta":{"ui":{"resourceUri":"ui://widget/visible"}},"name":"visible"}]}`
	})).Return(&appplugins.StageOutcome{}, nil).Once()
	g := mcphttp.NewRPCGatewayWithAppsListPolicy(
		composer, appmcp.NewPluginRunner(exec, discardLogger()), nil, enabledAppsListPolicy(t), mcphttp.DefaultMaxContinuationBytes,
	)
	err := g.OpenSubscriptionLease(
		context.Background(),
		mcpRoutableConsumer(),
		appmcp.NewHonouredSet(appmcp.NotificationToolsListChanged),
	)
	require.NoError(t, err)
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
		CallTool(mock.Anything, mock.Anything, toolCallNamed("echo")).
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
	composer.AssertNotCalled(t, "CallTool", mock.Anything, mock.Anything, mock.Anything)
}

func TestRPCGateway_ToolsCall_PreResponseBlock_DiscardsResult(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{"content":[{"type":"text","text":"secret"}]}`)
	composer := mocks.NewComposer(t)
	composer.EXPECT().CallTool(mock.Anything, mock.Anything, toolCallNamed("echo")).Return(raw, nil).Once()

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
	composer.EXPECT().CallTool(mock.Anything, mock.Anything, toolCallNamed("echo")).Return(raw, nil).Once()

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

// prompts/list and resources/list do not carry tool descriptions, so they never
// run the policy chain: the executor is wired with no RunStage expectation, and
// mockery fails the test if the chain runs.
func TestRPCGateway_ListingsWithoutTools_NeverRunPolicyChain(t *testing.T) {
	t.Parallel()
	cases := []struct {
		method string
		expect func(*mocks.Composer)
	}{
		{
			method: "prompts/list",
			expect: func(c *mocks.Composer) {
				c.EXPECT().ListPrompts(mock.Anything, mock.Anything).Return(nil, nil).Once()
			},
		},
		{
			method: "resources/list",
			expect: func(c *mocks.Composer) {
				c.EXPECT().ListResources(mock.Anything, mock.Anything).Return(nil, nil).Once()
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.method, func(t *testing.T) {
			t.Parallel()
			composer := mocks.NewComposer(t)
			tc.expect(composer)
			exec := pluginmocks.NewExecutor(t)

			g := mcphttp.NewRPCGateway(composer, appmcp.NewPluginRunner(exec, discardLogger()), nil)
			_, err := g.Dispatch(context.Background(), mcpRoutableConsumer(), tc.method, nil)
			require.NoError(t, err)
			exec.AssertNotCalled(t, "RunStage", mock.Anything, mock.Anything)
		})
	}
}

// tools/list is scanned for threats in the tool descriptions, but a data-masking
// transform (DLP) is ignored: masking static tool metadata is pointless, and
// blocking on it would leave the client with no tools. The listing is returned
// unchanged even though the guard short-circuited with a masked body.
func TestRPCGateway_ToolsList_IgnoresMaskingTransform(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).
		Return([]appmcp.Tool{{Name: "search"}}, nil).Once()

	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.MatchedBy(func(in appplugins.StageInput) bool {
		return in.Stage == policydomain.StagePreResponse
	})).Return(&appplugins.StageOutcome{
		ShortCircuit: true,
		StatusCode:   http.StatusOK,
		Body:         []byte(`{"tools":[{"name":"search","description":"[MASKED_EMAIL]"}]}`),
	}, nil).Once()

	g := mcphttp.NewRPCGateway(composer, appmcp.NewPluginRunner(exec, discardLogger()), nil)
	res, err := g.Dispatch(context.Background(), mcpRoutableConsumer(), "tools/list", nil)
	require.NoError(t, err)
	body, _ := json.Marshal(res)
	assert.Contains(t, string(body), `"search"`)
	assert.NotContains(t, string(body), "MASKED", "the listing must be returned unmasked")
}

// A genuine threat block on a tool description (indirect prompt injection, code
// injection) stops discovery with -32001.
func TestRPCGateway_ToolsList_ThreatBlockStopsDiscovery(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).
		Return([]appmcp.Tool{{Name: "search"}}, nil).Once()

	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).
		Return(nil, blockErr("injection")).Once()

	g := mcphttp.NewRPCGateway(composer, appmcp.NewPluginRunner(exec, discardLogger()), nil)
	res, err := g.Dispatch(context.Background(), mcpRoutableConsumer(), "tools/list", nil)
	assert.Nil(t, res)
	var rpcErr *appmcp.RPCError
	require.True(t, errors.As(err, &rpcErr), "want *appmcp.RPCError, got %v", err)
	assert.Equal(t, int64(-32001), rpcErr.Code)
}

// A policy denial answers HTTP 200 carrying the JSON-RPC error: MCP clients
// read a 4xx on this endpoint as a transport failure and tear the session down
// without ever surfacing the block. The 403 it means is recorded on the span.
func TestHandler_ToolsCall_PreRequestBlock_RidesOn200(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).Return(nil, blockErr("e2e")).Once()

	app := newAppWithRunner(t, composer, appmcp.NewPluginRunner(exec, discardLogger()), consumerdomain.TypeMCP, true)
	status, body := rpcCall(t, app, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"echo"}}`)

	if status != fiber.StatusOK {
		t.Fatalf("policy-blocked tools/call must ride on HTTP 200 so the client parses it, got %d", status)
	}
	rpcErr := body["error"].(map[string]any)
	if rpcErr["code"].(float64) != -32001 {
		t.Fatalf("code = %v, want -32001 policy blocked", rpcErr["code"])
	}
	composer.AssertNotCalled(t, "CallTool", mock.Anything, mock.Anything, mock.Anything)
}

func TestHandler_ToolsCall_RateLimitPropagatesHeaders(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).Return(nil, &appplugins.PluginError{
		StatusCode: 429,
		Type:       "trustguard_rate_limited",
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

	// Throttling rides on 200 for the same transport reason; the rate-limit
	// headers still travel so clients can back off.
	require.Equal(t, fiber.StatusOK, resp.StatusCode)
	require.Equal(t, "30", resp.Header.Get("Retry-After"))
	require.Equal(t, "quota", resp.Header.Get("X-RateLimit-Reason"))
	require.Equal(t, "10000", resp.Header.Get("X-RateLimit-Limit"))

	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	rpcErr := body["error"].(map[string]any)
	require.Equal(t, float64(-32004), rpcErr["code"])
	composer.AssertNotCalled(t, "CallTool", mock.Anything, mock.Anything, mock.Anything)
}

func TestRPCGateway_ToolsList_GatewayPlanExceeded_ReturnsRPCError(t *testing.T) {
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
	res, err := g.Dispatch(context.Background(), rc, "tools/list", nil)

	assert.Nil(t, res)
	var rpcErr *appmcp.RPCError
	require.True(t, errors.As(err, &rpcErr), "want *appmcp.RPCError, got %v", err)
	assert.Equal(t, appmcp.CodeRateLimited, rpcErr.Code)
	composer.AssertNotCalled(t, "ListTools", mock.Anything, mock.Anything)
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
	composer.AssertNotCalled(t, "CallTool", mock.Anything, mock.Anything, mock.Anything)
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

func TestRPCGateway_ToolsCall_GatewayPlanUnavailable_ReturnsRPCError(t *testing.T) {
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
	var rpcErr *appmcp.RPCError
	require.True(t, errors.As(err, &rpcErr), "want *appmcp.RPCError, got %v", err)
	assert.Equal(t, appmcp.CodeUnavailable, rpcErr.Code)
	composer.AssertNotCalled(t, "CallTool", mock.Anything, mock.Anything, mock.Anything)
}

// End to end: TrustGuard masks the tool input, and the masked arguments — not
// the originals — are what reaches the upstream. Forwarding the originals would
// leak exactly the data the policy was configured to redact.
func TestHandler_ToolsCall_MaskedArgumentsReachUpstream(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	var forwarded json.RawMessage
	composer.EXPECT().CallTool(mock.Anything, mock.Anything, toolCallNamed("echo")).
		Run(func(_ context.Context, _ *appconsumer.RoutableConsumer, call appmcp.ToolCall) {
			forwarded = call.Arguments
		}).
		Return(json.RawMessage(`{"content":[]}`), nil).Once()

	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).
		Run(func(_ context.Context, in appplugins.StageInput) {
			if in.Stage == policydomain.StagePreRequest {
				in.Request.Body = []byte(`{"name":"echo","arguments":{"ssn":"[REDACTED]"}}`)
			}
		}).
		Return(&appplugins.StageOutcome{}, nil)

	app := newAppWithRunner(t, composer, appmcp.NewPluginRunner(exec, discardLogger()), consumerdomain.TypeMCP, true)
	status, _ := rpcCall(t, app,
		`{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"echo","arguments":{"ssn":"123-45-6789"}}}`)

	require.Equal(t, fiber.StatusOK, status)
	assert.JSONEq(t, `{"ssn":"[REDACTED]"}`, string(forwarded),
		"the upstream must receive the masked arguments")
}

// End to end: a masked tool result reaches the client as the tool's output
// rather than failing the call.
func TestHandler_ToolsCall_MaskedResultReachesClient(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().CallTool(mock.Anything, mock.Anything, toolCallNamed("echo")).
		Return(json.RawMessage(`{"content":[{"type":"text","text":"555-1234"}]}`), nil).Once()

	masked := `{"content":[{"type":"text","text":"[REDACTED]"}]}`
	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, in appplugins.StageInput) (*appplugins.StageOutcome, error) {
			if in.Stage == policydomain.StagePreResponse {
				return &appplugins.StageOutcome{
					ShortCircuit: true,
					StatusCode:   fiber.StatusOK,
					Body:         []byte(masked),
				}, nil
			}
			return &appplugins.StageOutcome{}, nil
		})

	app := newAppWithRunner(t, composer, appmcp.NewPluginRunner(exec, discardLogger()), consumerdomain.TypeMCP, true)
	status, body := rpcCall(t, app, `{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{"name":"echo"}}`)

	require.Equal(t, fiber.StatusOK, status)
	require.Nil(t, body["error"], "masking must not fail the call: %v", body["error"])
	got, err := json.Marshal(body["result"])
	require.NoError(t, err)
	assert.JSONEq(t, masked, string(got))
}
