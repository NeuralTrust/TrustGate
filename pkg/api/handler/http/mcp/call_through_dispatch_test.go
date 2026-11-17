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
	"testing"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func callThroughGateway(t *testing.T, composer *mocks.Composer, runner *appmcp.PluginRunner) *mcphttp.RPCGateway {
	t.Helper()
	inventory, err := appmcp.NewInventoryTool(composer, nil)
	require.NoError(t, err)
	return mcphttp.NewRPCGateway(composer, runner, nil).WithInventoryTool(inventory)
}

func callThrough(inner string) json.RawMessage {
	return json.RawMessage(`{"name":"` + appmcp.CallToolName + `","arguments":` + inner + `}`)
}

// A tool the client never listed — Claude's hosted connector keeps the list it
// fetched when the connector was added — is reached by name, with its own
// arguments, and its own result comes back.
func TestRPCGateway_CallThroughCallsTheNamedTool(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	var forwarded json.RawMessage
	target := expectResolve(composer, "linear_save_issue")
	composer.EXPECT().Invoke(mock.Anything, mock.Anything, target, mock.Anything).
		Run(func(_ context.Context, _ *appconsumer.RoutableConsumer, _ *appmcp.ResolvedTool, args json.RawMessage) {
			forwarded = args
		}).
		Return(json.RawMessage(`{"content":[{"type":"text","text":"created"}]}`), nil).Once()

	rt := trace.New("t-call-through", trace.Metadata{Kind: events.KindMCP})
	ctx := trace.NewContext(context.Background(), rt)
	result, err := callThroughGateway(t, composer, noopRunner()).Dispatch(ctx, inventoryConsumer(t), "tools/call",
		callThrough(`{"name":"linear_save_issue","arguments":{"title":"Bug"}}`))
	require.NoError(t, err)

	assert.JSONEq(t, `{"title":"Bug"}`, string(forwarded))
	raw, err := json.Marshal(result)
	require.NoError(t, err)
	assert.Contains(t, string(raw), "created")

	// Activity names the tool that ran, and usage counts it as the user's.
	attrs, ok := rt.Spans()[0].MCPAttrsCopy()
	require.True(t, ok)
	assert.Equal(t, "linear_save_issue", attrs.Tool)
	assert.Equal(t, "upstream", attrs.ServerName)
	assert.False(t, rt.IsMetaTool(), "a call-through that ran a tool is that tool's call")
}

// The wrapper is not a way round policy: the request stages see the tool that
// is called and its arguments, exactly as for a direct call, and what they
// rewrite is what reaches the upstream.
func TestRPCGateway_CallThroughRunsTheCalledToolsPolicies(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	var forwarded json.RawMessage
	target := expectResolve(composer, "linear_save_issue")
	composer.EXPECT().Invoke(mock.Anything, mock.Anything, target, mock.Anything).
		Run(func(_ context.Context, _ *appconsumer.RoutableConsumer, _ *appmcp.ResolvedTool, args json.RawMessage) {
			forwarded = args
		}).
		Return(json.RawMessage(`{"content":[]}`), nil).Once()

	var seen string
	exec := pluginmocks.NewExecutor(t)
	exec.EXPECT().RunStage(mock.Anything, mock.Anything).
		Run(func(_ context.Context, in appplugins.StageInput) {
			if in.Stage == policydomain.StagePreRequest {
				seen = string(in.Request.Body)
				in.Request.Body = []byte(`{"name":"linear_save_issue","arguments":{"title":"[REDACTED]"}}`)
			}
		}).
		Return(&appplugins.StageOutcome{}, nil)

	_, err := callThroughGateway(t, composer, appmcp.NewPluginRunner(exec, discardLogger())).
		Dispatch(context.Background(), inventoryConsumer(t), "tools/call",
			callThrough(`{"name":"linear_save_issue","arguments":{"title":"secret"}}`))
	require.NoError(t, err)

	assert.JSONEq(t, `{"name":"linear_save_issue","arguments":{"title":"secret"}}`, seen)
	assert.JSONEq(t, `{"title":"[REDACTED]"}`, string(forwarded))
}

// A tool the caller may not use is refused through the wrapper the way it is
// refused directly.
func TestRPCGateway_CallThroughKeepsTheToolsRefusal(t *testing.T) {
	t.Parallel()
	refusal := &appmcp.ToolNotPermittedError{Tool: "linear_delete_issue"}
	composer := mocks.NewComposer(t)
	composer.EXPECT().Resolve(mock.Anything, mock.Anything, "linear_delete_issue").Return(nil, refusal).Once()

	_, err := callThroughGateway(t, composer, noopRunner()).Dispatch(context.Background(), inventoryConsumer(t), "tools/call",
		callThrough(`{"name":"linear_delete_issue"}`))
	var notPermitted *appmcp.ToolNotPermittedError
	require.ErrorAs(t, err, &notPermitted)
	assert.Equal(t, "linear_delete_issue", notPermitted.Tool)
}

// A model that writes the arguments as a JSON string means the object in it.
func TestRPCGateway_CallThroughReadsStringEncodedArguments(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	var forwarded json.RawMessage
	target := expectResolve(composer, "linear_save_issue")
	composer.EXPECT().Invoke(mock.Anything, mock.Anything, target, mock.Anything).
		Run(func(_ context.Context, _ *appconsumer.RoutableConsumer, _ *appmcp.ResolvedTool, args json.RawMessage) {
			forwarded = args
		}).
		Return(json.RawMessage(`{"content":[]}`), nil).Once()

	_, err := callThroughGateway(t, composer, noopRunner()).Dispatch(context.Background(), inventoryConsumer(t), "tools/call",
		callThrough(`{"name":"linear_save_issue","arguments":"{\"title\":\"Bug\"}"}`))
	require.NoError(t, err)
	assert.JSONEq(t, `{"title":"Bug"}`, string(forwarded))
}

// What the model got wrong comes back as a tool error it can read and fix, and
// nothing reaches an upstream.
func TestRPCGateway_CallThroughRefusesWhatItCannotCall(t *testing.T) {
	t.Parallel()
	for name, inner := range map[string]string{
		"no name":                  `{}`,
		"blank name":               `{"name":"  "}`,
		"itself":                   `{"name":"` + appmcp.CallToolName + `"}`,
		"a Store tool":             `{"name":"` + appmcp.StoreInstallToolName + `","arguments":{"code":"app.linear/mcp"}}`,
		"the inventory":            `{"name":"` + appmcp.InventoryToolName + `"}`,
		"arguments not an object":  `{"name":"linear_save_issue","arguments":[1,2]}`,
		"arguments not JSON":       `{"name":"linear_save_issue","arguments":"not json"}`,
		"a wrapper that is no map": `"linear_save_issue"`,
	} {
		composer := mocks.NewComposer(t)
		rt := trace.New("t-refused", trace.Metadata{Kind: events.KindMCP})
		ctx := trace.NewContext(context.Background(), rt)

		result, err := callThroughGateway(t, composer, noopRunner()).Dispatch(ctx, inventoryConsumer(t), "tools/call", callThrough(inner))
		require.NoError(t, err, name)
		raw, ok := result.(json.RawMessage)
		require.True(t, ok, "%s: result = %T", name, result)
		var decoded struct {
			IsError bool `json:"isError"`
		}
		require.NoError(t, json.Unmarshal(raw, &decoded), name)
		assert.True(t, decoded.IsError, "%s: want a tool error, got %s", name, raw)
		assert.True(t, rt.IsMetaTool(), "%s: a call-through that ran nothing is the gateway's own", name)
	}
}

// Without the inventory there is no way to learn a tool's name or schema, so
// the call-through is neither offered nor answered.
func TestRPCGateway_CallThroughNeedsTheInventory(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return(nil, nil).Once()
	composer.EXPECT().Resolve(mock.Anything, mock.Anything, appmcp.CallToolName).Return(nil, appmcp.ErrToolNotFound).Once()
	g := mcphttp.NewRPCGateway(composer, noopRunner(), nil)

	listed, err := g.Dispatch(context.Background(), inventoryConsumer(t), "tools/list", nil)
	require.NoError(t, err)
	require.NotContains(t, toolNames(listed.(map[string]any)["tools"].([]appmcp.Tool)), appmcp.CallToolName)

	_, err = g.Dispatch(context.Background(), inventoryConsumer(t), "tools/call", callThrough(`{"name":"linear_save_issue"}`))
	require.ErrorIs(t, err, appmcp.ErrToolNotFound)
}
