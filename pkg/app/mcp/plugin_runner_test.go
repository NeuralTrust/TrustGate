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
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
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

			err := runner.PreRequest(context.Background(), rc, testToolName, json.RawMessage(testToolArgs))

			assertStageInput(t, captured, policydomain.StagePreRequest, rc)
			assert.Nil(t, captured.Response)

			switch {
			case tt.wantNil:
				require.NoError(t, err)
			case tt.wantRPCCode != 0:
				assertRPCError(t, err, tt.wantRPCCode, tt.wantRPCData)
			}
		})
	}
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

			err := runner.PreResponse(
				context.Background(),
				rc,
				testToolName,
				json.RawMessage(testToolArgs),
				json.RawMessage(testResult),
			)

			assertStageInput(t, captured, policydomain.StagePreResponse, rc)
			require.NotNil(t, captured.Response)
			assert.False(t, captured.Response.Streaming)
			assert.JSONEq(t, testResult, string(captured.Response.Body))

			switch {
			case tt.wantNil:
				require.NoError(t, err)
			case tt.wantRPCCode != 0:
				assertRPCError(t, err, tt.wantRPCCode, tt.wantRPCData)
			}
		})
	}
}

func TestPluginRunner_NilExecutor(t *testing.T) {
	t.Parallel()

	runner := NewPluginRunner(nil, discardLogger())
	rc := routableMCPConsumer()

	require.NoError(t, runner.PreRequest(context.Background(), rc, testToolName, json.RawMessage(testToolArgs)))
	require.NoError(t, runner.PreResponse(
		context.Background(), rc, testToolName, json.RawMessage(testToolArgs), json.RawMessage(testResult),
	))
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

func assertRPCError(t *testing.T, err error, code int64, data string) {
	t.Helper()
	var rpcErr *RPCError
	require.True(t, errors.As(err, &rpcErr), "expected *RPCError, got %v", err)
	assert.Equal(t, code, rpcErr.Code)
	if data != "" {
		assert.JSONEq(t, data, string(rpcErr.Data))
	}
}
