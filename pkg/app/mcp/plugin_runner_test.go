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
	"io"
	"log/slog"
	"net/http"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	testToolName = "search"
	testToolArgs = `{"q":"hello"}`
	testResult   = `{"content":[{"type":"text","text":"world"}]}`
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func routableMCPConsumer(policies ...*policydomain.Policy) *appconsumer.RoutableConsumer {
	return &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{Type: consumerdomain.TypeMCP},
		Policies: policies,
	}
}

func preResponsePolicy(stages ...policydomain.Stage) *policydomain.Policy {
	return &policydomain.Policy{
		Enabled: true,
		Mode:    policydomain.ModeEnforce,
		Stages:  stages,
	}
}

func unboundCall() ToolCall {
	return ToolCall{Exposed: testToolName, NativeTool: testToolName, Arguments: json.RawMessage(testToolArgs)}
}

func TestPluginRunner_PreRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		outcome     *appplugins.StageOutcome
		execErr     error
		wantRPCCode int64
		wantRPCData string
		wantNil     bool
	}{
		{
			name:    "allow",
			outcome: &appplugins.StageOutcome{},
			wantNil: true,
		},
		{
			name:    "report does not block",
			outcome: &appplugins.StageOutcome{ShortCircuit: false},
			wantNil: true,
		},
		{
			name:        "enforce block via plugin error",
			execErr:     &appplugins.PluginError{StatusCode: 403, Message: "blocked", Body: []byte(`{"trace_id":"t1"}`)},
			wantRPCCode: codePolicyBlocked,
			wantRPCData: `{"trace_id":"t1"}`,
		},
		{
			name:        "enforce block via short circuit",
			outcome:     &appplugins.StageOutcome{ShortCircuit: true, StatusCode: 403, Body: []byte(`{"trace_id":"t2"}`)},
			wantRPCCode: codePolicyBlocked,
			wantRPCData: `{"trace_id":"t2"}`,
		},
		{
			name: "trustguard plan rate limit via plugin error",
			execErr: &appplugins.PluginError{
				StatusCode: 429,
				Type:       "trustguard_rate_limited",
				Message:    "rate limit exceeded",
				Body:       []byte(`{"error":"rate limit exceeded","reason":"burst"}`),
				Headers:    map[string][]string{"Retry-After": {"42"}, "X-RateLimit-Reason": {"burst"}},
			},
			wantRPCCode: CodeRateLimited,
			wantRPCData: `{"error":"rate limit exceeded","reason":"burst"}`,
		},
		{
			name: "trustguard entitlements unavailable via plugin error",
			execErr: &appplugins.PluginError{
				StatusCode: 503,
				Type:       "trustguard_unavailable",
				Message:    "rate limit entitlements unavailable",
				Body:       []byte(`{"error":"rate limit entitlements unavailable"}`),
			},
			wantRPCCode: CodeUnavailable,
			wantRPCData: `{"error":"rate limit entitlements unavailable"}`,
		},
		{
			// A tool budget is a matter of timing, so it gets the code a client
			// can act on rather than the one that means "never".
			name: "policy rate limit 429 is throttling, not a veto",
			execErr: &appplugins.PluginError{
				StatusCode: 429,
				Message:    "tool rate limit exceeded",
				Body:       []byte(`{"error":"rate limit exceeded"}`),
				Headers:    map[string][]string{"X-RateLimit-Tool": {"send_email"}},
			},
			wantRPCCode: CodeRateLimited,
			wantRPCData: `{"error":"rate limit exceeded"}`,
		},
		{
			name:    "generic executor error fails open",
			execErr: errors.New("boom"),
			wantNil: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			exec := pluginmocks.NewExecutor(t)
			var captured appplugins.StageInput
			exec.EXPECT().RunStage(mock.Anything, mock.Anything).
				Run(func(_ context.Context, in appplugins.StageInput) { captured = in }).
				Return(tt.outcome, tt.execErr)

			rc := routableMCPConsumer(preResponsePolicy(policydomain.StagePreRequest))
			runner := NewPluginRunner(exec, discardLogger())

			_, err := runner.PreRequest(context.Background(), rc, unboundCall())

			assertStageInput(t, captured, policydomain.StagePreRequest, rc)
			assert.Nil(t, captured.Response)

			switch {
			case tt.wantNil:
				require.NoError(t, err)
			case tt.wantRPCCode != 0:
				rpcErr := assertRPCError(t, err, tt.wantRPCCode, tt.wantRPCData)
				assert.Equal(t, expectedHTTPStatus(tt.execErr, tt.outcome), rpcErr.HTTPStatus)
				// The headers are how a throttled client learns when to come
				// back, so whatever the plugin set has to survive the trip.
				var pe *appplugins.PluginError
				if errors.As(tt.execErr, &pe) && len(pe.Headers) > 0 {
					assert.Equal(t, pe.Headers, rpcErr.HTTPHeaders)
				}
			}
		})
	}
}

func expectedHTTPStatus(execErr error, outcome *appplugins.StageOutcome) int {
	var pe *appplugins.PluginError
	if errors.As(execErr, &pe) && pe.StatusCode != 0 {
		return pe.StatusCode
	}
	if outcome != nil && outcome.StatusCode != 0 {
		return outcome.StatusCode
	}
	return http.StatusForbidden
}

func TestPluginRunner_PreResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		plan        []policydomain.Stage
		outcome     *appplugins.StageOutcome
		execErr     error
		wantRPCCode int64
		wantRPCData string
		wantNil     bool
	}{
		{
			name:    "allow",
			plan:    []policydomain.Stage{policydomain.StagePreResponse},
			wantNil: true,
		},
		{
			name:    "report does not block",
			plan:    []policydomain.Stage{policydomain.StagePreResponse},
			wantNil: true,
		},
		{
			name:        "enforce block via plugin error",
			plan:        []policydomain.Stage{policydomain.StagePreResponse},
			execErr:     &appplugins.PluginError{StatusCode: 403, Message: "blocked", Body: []byte(`{"trace_id":"t3"}`)},
			wantRPCCode: codePolicyBlocked,
			wantRPCData: `{"trace_id":"t3"}`,
		},
		{
			name:        "enforce block via short circuit",
			plan:        []policydomain.Stage{policydomain.StagePreResponse},
			outcome:     &appplugins.StageOutcome{ShortCircuit: true, StatusCode: 403, Body: []byte(`{"trace_id":"t4"}`)},
			wantRPCCode: codePolicyBlocked,
			wantRPCData: `{"trace_id":"t4"}`,
		},
		{
			name:    "generic error fails open even when plan blocks pre_response",
			plan:    []policydomain.Stage{policydomain.StagePreResponse},
			execErr: errors.New("guard down"),
			wantNil: true,
		},
		{
			name:    "generic error fails open when plan does not block",
			plan:    []policydomain.Stage{policydomain.StagePreRequest},
			execErr: errors.New("guard down"),
			wantNil: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			exec := pluginmocks.NewExecutor(t)
			var captured appplugins.StageInput
			outcome := tt.outcome
			if outcome == nil {
				outcome = &appplugins.StageOutcome{}
			}
			exec.EXPECT().RunStage(mock.Anything, mock.Anything).
				Run(func(_ context.Context, in appplugins.StageInput) { captured = in }).
				Return(outcome, tt.execErr)

			rc := routableMCPConsumer(preResponsePolicy(tt.plan...))
			runner := NewPluginRunner(exec, discardLogger())

			_, err := runner.PreResponse(context.Background(), rc, unboundCall(), json.RawMessage(testResult))

			assertStageInput(t, captured, policydomain.StagePreResponse, rc)
			require.NotNil(t, captured.Response)
			assert.False(t, captured.Response.Streaming)
			assert.JSONEq(t, testResult, string(captured.Response.Body))

			switch {
			case tt.wantNil:
				require.NoError(t, err)
			case tt.wantRPCCode != 0:
				rpcErr := assertRPCError(t, err, tt.wantRPCCode, tt.wantRPCData)
				assert.Equal(t, expectedHTTPStatus(tt.execErr, tt.outcome), rpcErr.HTTPStatus)
			}
		})
	}
}

func TestPluginRunner_NilExecutor(t *testing.T) {
	t.Parallel()

	runner := NewPluginRunner(nil, discardLogger())
	rc := routableMCPConsumer()

	_, err := runner.PreRequest(context.Background(), rc, unboundCall())
	require.NoError(t, err)
	_, err = runner.PreResponse(context.Background(), rc, unboundCall(), json.RawMessage(testResult))
	require.NoError(t, err)
}

// A resolved call travels to the plugins with the binding Resolve fixed:
// RegistryID and the native tool in metadata, while Body.name stays the exposed
// name the caller used. A plugin decides on the native tool; the gateway keeps
// routing on the resolved target, so a rewritten name has nowhere to go.
func TestPluginRunner_ResolvedCall_CarriesNativeBinding(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "snowflake", "https://snowflake.example.com/mcp")
	call := ToolCall{
		Exposed:    "mcp_ab12_run_query_9f8e",
		Registry:   reg,
		NativeTool: "run_query",
		Arguments:  json.RawMessage(testToolArgs),
	}
	wantBody := `{"name":"mcp_ab12_run_query_9f8e","arguments":` + testToolArgs + `}`

	assertBinding := func(t *testing.T, in appplugins.StageInput) {
		t.Helper()
		require.NotNil(t, in.Request)
		assert.Equal(t, reg.ID.String(), in.Request.RegistryID)
		assert.Equal(t, "run_query", in.Request.Metadata[infracontext.MetadataMCPTool])
		assert.Equal(t, reg.ID.String(), in.Request.Metadata[infracontext.MetadataMCPRegistryID])
		assert.Equal(t, "snowflake", in.Request.Metadata[infracontext.MetadataMCPRegistryName])
		assert.Equal(t, "mcp_ab12_run_query_9f8e", in.Request.Metadata[infracontext.MetadataMCPExposedTool])
		assert.JSONEq(t, wantBody, string(in.Request.Body))
	}

	t.Run("pre_request", func(t *testing.T) {
		t.Parallel()
		exec := pluginmocks.NewExecutor(t)
		var captured appplugins.StageInput
		exec.EXPECT().RunStage(mock.Anything, mock.Anything).
			Run(func(_ context.Context, in appplugins.StageInput) { captured = in }).
			Return(&appplugins.StageOutcome{}, nil).Once()
		runner := NewPluginRunner(exec, discardLogger())

		_, err := runner.PreRequest(context.Background(), routableMCPConsumer(), call)
		require.NoError(t, err)
		assert.Equal(t, policydomain.StagePreRequest, captured.Stage)
		assertBinding(t, captured)
	})

	t.Run("pre_response", func(t *testing.T) {
		t.Parallel()
		exec := pluginmocks.NewExecutor(t)
		var captured appplugins.StageInput
		exec.EXPECT().RunStage(mock.Anything, mock.Anything).
			Run(func(_ context.Context, in appplugins.StageInput) { captured = in }).
			Return(&appplugins.StageOutcome{}, nil).Once()
		runner := NewPluginRunner(exec, discardLogger())

		_, err := runner.PreResponse(context.Background(), routableMCPConsumer(), call, json.RawMessage(testResult))
		require.NoError(t, err)
		assert.Equal(t, policydomain.StagePreResponse, captured.Stage)
		assertBinding(t, captured)
		require.NotNil(t, captured.Response)
		assert.JSONEq(t, testResult, string(captured.Response.Body))
	})
}

// A call without a Registry has no binding to report: RegistryID and Metadata
// stay empty, and the body is byte-identical to what the runner has always
// sent.
func TestPluginRunner_UnboundCall_CarriesNoBinding(t *testing.T) {
	t.Parallel()
	exec := pluginmocks.NewExecutor(t)
	var captured appplugins.StageInput
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).
		Run(func(_ context.Context, in appplugins.StageInput) { captured = in }).
		Return(&appplugins.StageOutcome{}, nil).Once()
	runner := NewPluginRunner(exec, discardLogger())
	rc := routableMCPConsumer(preResponsePolicy(policydomain.StagePreRequest))

	_, err := runner.PreRequest(context.Background(), rc, unboundCall())
	require.NoError(t, err)
	assertStageInput(t, captured, policydomain.StagePreRequest, rc)
	assert.Empty(t, captured.Request.RegistryID)
	assert.Nil(t, captured.Request.Metadata)
}

// The plan PlanFor picked for the destination is what the executor runs, and
// it runs alone: Policies stays empty so the executor cannot fall back to
// rebuilding the consumer-wide chain. Without a plan the stage keeps today's
// inputs, so a consumer without MCPPlans still resolves through in.Policies.
func TestPluginRunner_StagePlanSelection(t *testing.T) {
	t.Parallel()
	scoped := &appplugins.StagePlan{}
	basePlan := &appplugins.StagePlan{}
	newRC := func() *appconsumer.RoutableConsumer {
		rc := routableMCPConsumer(preResponsePolicy(policydomain.StagePreRequest, policydomain.StagePreResponse))
		rc.PolicyPlan = basePlan
		return rc
	}

	tests := []struct {
		name         string
		plan         *appplugins.StagePlan
		wantPlan     *appplugins.StagePlan
		wantPolicies bool
	}{
		{name: "resolved plan is used as is", plan: scoped, wantPlan: scoped},
		{name: "nil plan falls back to the consumer plan", wantPlan: basePlan, wantPolicies: true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rc := newRC()
			exec := pluginmocks.NewExecutor(t)
			exec.EXPECT().RunStage(mock.Anything, mock.MatchedBy(func(in appplugins.StageInput) bool {
				return in.Plan == tt.wantPlan && (len(in.Policies) > 0) == tt.wantPolicies
			})).Return(&appplugins.StageOutcome{}, nil).Twice()
			runner := NewPluginRunner(exec, discardLogger())
			call := ToolCall{Exposed: testToolName, NativeTool: testToolName, Arguments: json.RawMessage(testToolArgs), Plan: tt.plan}

			_, err := runner.PreRequest(context.Background(), rc, call)
			require.NoError(t, err)
			_, err = runner.PreResponse(context.Background(), rc, call, json.RawMessage(testResult))
			require.NoError(t, err)
		})
	}
}

func assertStageInput(t *testing.T, in appplugins.StageInput, stage policydomain.Stage, rc *appconsumer.RoutableConsumer) {
	t.Helper()
	assert.Equal(t, stage, in.Stage)
	assert.Equal(t, rc.Policies, in.Policies)
	assert.Equal(t, rc.PolicyPlan, in.Plan)
	require.NotNil(t, in.Request)
	assert.True(t, in.Request.MCP)
	assert.Equal(t, "MCP", in.Request.ConsumerType)
	assert.Equal(t, rc.Consumer.GatewayID.String(), in.Request.GatewayID)
	assert.Equal(t, rc.Consumer.ID.String(), in.Request.ConsumerID)
	assert.Empty(t, in.Request.Provider)
	assert.Empty(t, in.Request.SessionID)
	assert.JSONEq(t, `{"name":"`+testToolName+`","arguments":`+testToolArgs+`}`, string(in.Request.Body))
}

func assertRPCError(t *testing.T, err error, code int64, data string) *RPCError {
	t.Helper()
	var rpcErr *RPCError
	require.True(t, errors.As(err, &rpcErr), "expected *RPCError, got %v", err)
	assert.Equal(t, code, rpcErr.Code)
	if data != "" {
		assert.JSONEq(t, data, string(rpcErr.Data))
	}
	return rpcErr
}

// TrustGuard data-masking rewrites the request body in place instead of
// blocking. The runner has to read the masked arguments back out: forwarding
// the originals would send upstream exactly what the plugin just redacted.
func TestPluginRunner_PreRequest_ReturnsMaskedArguments(t *testing.T) {
	t.Parallel()
	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).
		Run(func(_ context.Context, in appplugins.StageInput) {
			in.Request.Body = []byte(`{"name":"search","arguments":{"q":"[REDACTED]"}}`)
		}).
		Return(&appplugins.StageOutcome{}, nil).Once()

	runner := NewPluginRunner(exec, discardLogger())
	rc := routableMCPConsumer(preResponsePolicy(policydomain.StagePreRequest))

	got, err := runner.PreRequest(context.Background(), rc, unboundCall())
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.JSONEq(t, `{"q":"[REDACTED]"}`, string(got.Arguments))
}

// Untouched arguments must not be reported as a rewrite, so the caller keeps
// forwarding the value it already has.
func TestPluginRunner_PreRequest_NoRewriteLeavesArgumentsEmpty(t *testing.T) {
	t.Parallel()
	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).
		Return(&appplugins.StageOutcome{}, nil).Once()

	runner := NewPluginRunner(exec, discardLogger())
	rc := routableMCPConsumer(preResponsePolicy(policydomain.StagePreRequest))

	got, err := runner.PreRequest(context.Background(), rc, unboundCall())
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Nil(t, got.Arguments)
}

// A masked tool result arrives as a 2xx short-circuit carrying a body. That is
// a rewrite, not a denial: the masked payload becomes the tool's output.
func TestPluginRunner_PreResponse_MaskedResultReplacesOutput(t *testing.T) {
	t.Parallel()
	masked := `{"content":[{"type":"text","text":"[REDACTED]"}]}`
	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).
		Return(&appplugins.StageOutcome{
			ShortCircuit: true,
			StatusCode:   http.StatusOK,
			Body:         []byte(masked),
		}, nil).Once()

	runner := NewPluginRunner(exec, discardLogger())
	rc := routableMCPConsumer(preResponsePolicy(policydomain.StagePreResponse))

	got, err := runner.PreResponse(context.Background(), rc, unboundCall(), json.RawMessage(testResult))
	require.NoError(t, err, "a masked result must not fail the call")
	require.NotNil(t, got)
	assert.JSONEq(t, masked, string(got.Result))
}

// A non-2xx short-circuit is still a denial and must fail the call.
func TestPluginRunner_PreResponse_NonSuccessShortCircuitBlocks(t *testing.T) {
	t.Parallel()
	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).
		Return(&appplugins.StageOutcome{
			ShortCircuit: true,
			StatusCode:   http.StatusForbidden,
			Body:         []byte(`{"reason":"blocked"}`),
		}, nil).Once()

	runner := NewPluginRunner(exec, discardLogger())
	rc := routableMCPConsumer(preResponsePolicy(policydomain.StagePreResponse))

	_, err := runner.PreResponse(context.Background(), rc, unboundCall(), json.RawMessage(testResult))
	var rpcErr *RPCError
	require.ErrorAs(t, err, &rpcErr)
	assert.True(t, IsPolicyBlockedCode(rpcErr.Code))
}
