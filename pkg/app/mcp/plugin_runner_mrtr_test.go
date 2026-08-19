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
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const testInputResponses = `{"q1":{"action":"accept","content":{"ssn":"123-45-6789"}}}`

// Continuation answers are user input like any other, so a scanning plugin must
// see them and its rewrite must be what reaches the upstream.
func TestPluginRunner_PreRequest_ScansAndRewritesInputResponses(t *testing.T) {
	t.Parallel()
	masked := `{"q1":{"action":"accept","content":{"ssn":"[REDACTED]"}}}`
	var seen json.RawMessage
	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).
		Run(func(_ context.Context, in appplugins.StageInput) {
			var params mcpToolCallParams
			require.NoError(t, json.Unmarshal(in.Request.Body, &params))
			seen = params.InputResponses
			in.Request.Body = []byte(`{"name":"` + testToolName + `","arguments":` + testToolArgs +
				`,"inputResponses":` + masked + `}`)
		}).
		Return(&appplugins.StageOutcome{}, nil).Once()

	runner := NewPluginRunner(exec, discardLogger())
	result, err := runner.PreRequest(
		context.Background(),
		routableMCPConsumer(preResponsePolicy()),
		testToolName,
		json.RawMessage(testToolArgs),
		json.RawMessage(testInputResponses),
	)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.JSONEq(t, testInputResponses, string(seen), "plugins must see the continuation answers")
	require.JSONEq(t, masked, string(result.InputResponses))
	require.Empty(t, result.Arguments, "unchanged arguments must not be reported as rewritten")
}

// A plugin may not reroute the call, and the warning it earns must not carry the
// user's answers into the logs.
func TestPluginRunner_PreRequest_IgnoresToolNameAndKeepsAnswersOutOfLogs(t *testing.T) {
	t.Parallel()
	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).
		Run(func(_ context.Context, in appplugins.StageInput) {
			in.Request.Body = []byte(`{"name":"other-tool","arguments":` + testToolArgs +
				`,"inputResponses":` + testInputResponses + `}`)
		}).
		Return(&appplugins.StageOutcome{}, nil).Once()

	var logs bytes.Buffer
	runner := NewPluginRunner(exec, slog.New(slog.NewTextHandler(&logs, nil)))
	result, err := runner.PreRequest(
		context.Background(),
		routableMCPConsumer(preResponsePolicy()),
		testToolName,
		json.RawMessage(testToolArgs),
		json.RawMessage(testInputResponses),
	)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Empty(t, result.InputResponses, "an unchanged continuation must not be reported as rewritten")
	require.Contains(t, logs.String(), "ignoring the change")
	require.NotContains(t, logs.String(), "123-45-6789")
}
