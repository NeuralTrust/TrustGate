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
	"sort"
	"testing"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// newClientCtx is a request from a person signed in through the gateway.
func newClientCtx() context.Context {
	return identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "alice", Method: identity.MethodOAuth})
}

func appConsumer() *appconsumer.RoutableConsumer {
	return &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{
		ID:        ids.New[ids.ConsumerKind](),
		GatewayID: ids.New[ids.GatewayKind](),
		Slug:      "research",
		Type:      consumerdomain.TypeMCP,
	}}
}

func storeConsumer() *appconsumer.RoutableConsumer {
	return &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(ids.New[ids.GatewayKind]())}
}

func upstreamTool(t *testing.T, name, description, schema string) appmcp.Tool {
	t.Helper()
	raw := `{"name":"` + name + `","description":"` + description + `","inputSchema":` + schema + `}`
	var tool appmcp.Tool
	require.NoError(t, json.Unmarshal([]byte(raw), &tool))
	return tool
}

// linearSurface is an application with Linear connected and GitHub waiting on
// the person's account.
func linearSurface() *appmcp.ToolInventory {
	return &appmcp.ToolInventory{Servers: []appmcp.InventoryServer{
		{
			Name:  "Linear",
			Code:  "app.linear/mcp",
			State: appmcp.InventoryStateReady,
			Tools: []appmcp.InventoryEntry{
				{Name: "linear_list_issues", Description: "List issues in the user's Linear workspace.", Callable: true, Risk: appmcp.ToolRiskReadOnly,
					InputSchema: json.RawMessage(`{"type":"object","properties":{"assignee":{"type":"string"}}}`)},
				{Name: "linear_save_comment", Description: "Add a comment to a Linear issue.", Callable: true, Risk: appmcp.ToolRiskAdditive,
					InputSchema: json.RawMessage(`{"type":"object","properties":{"issueId":{"type":"string"},"body":{"type":"string"}},"required":["issueId","body"]}`)},
			},
		},
		{
			Name:     "GitHub",
			Code:     "com.github/mcp",
			State:    appmcp.InventoryStateNeedsConnect,
			Provider: "github",
			Cause:    "no_credential",
		},
	}}
}

func linearUpstreamTools(t *testing.T) []appmcp.Tool {
	return []appmcp.Tool{
		upstreamTool(t, "linear_list_issues", "List issues in the user's Linear workspace.", `{"type":"object"}`),
		upstreamTool(t, "linear_save_comment", "Add a comment to a Linear issue.", `{"type":"object"}`),
	}
}

func appGateway(t *testing.T, composer *mocks.Composer, statuses []appoauth.ProviderStatus) *mcphttp.RPCGateway {
	t.Helper()
	connections, err := appmcp.NewConnectionTool(&dispatcherTicketCreator{ticket: "tk", statuses: statuses})
	require.NoError(t, err)
	inventory, err := appmcp.NewInventoryTool(composer, nil)
	require.NoError(t, err)
	return mcphttp.NewRPCGatewayWithConnections(composer, noopRunner(), nil, connections).WithInventoryTool(inventory)
}

func listedNames(t *testing.T, listed any) []string {
	t.Helper()
	return toolNames(listed.(map[string]any)["tools"].([]appmcp.Tool))
}

func resultOf(t *testing.T, result any) (text string, structured map[string]any, isError bool) {
	t.Helper()
	raw, err := json.Marshal(result)
	require.NoError(t, err)
	var envelope struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		StructuredContent map[string]any `json:"structuredContent"`
		IsError           bool           `json:"isError"`
	}
	require.NoError(t, json.Unmarshal(raw, &envelope))
	for _, block := range envelope.Content {
		text += block.Text
	}
	return text, envelope.StructuredContent, envelope.IsError
}

func call(name, arguments string) json.RawMessage {
	return json.RawMessage(`{"name":"` + name + `","arguments":` + arguments + `}`)
}

// Every connection is offered the user's tools and the three consolidated
// ones — never the per-provider connect tools, the inventory or the
// call-through.
func TestConsolidated_ListOffersTheThreeTools(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return(linearUpstreamTools(t), nil).Once()
	g := appGateway(t, composer, []appoauth.ProviderStatus{{Provider: "github"}})

	listed, err := g.Dispatch(newClientCtx(), appConsumer(), "tools/list", nil)
	require.NoError(t, err)
	assert.Equal(t, []string{
		"linear_list_issues", "linear_save_comment",
		appmcp.SearchToolName, appmcp.GatewayCallToolName, appmcp.AccessToolName,
	}, listedNames(t, listed))
}

// The earlier tools are no longer listed but still answer: a client that kept
// the list it fetched before — Claude's hosted connectors keep theirs until
// the person reconnects — keeps working.
func TestConsolidated_EarlierToolsStillAnswer(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ToolInventory(mock.Anything, mock.Anything).Return(linearSurface(), nil).Once()
	g := appGateway(t, composer, []appoauth.ProviderStatus{{Provider: "github"}})
	ctx := newClientCtx()

	_, structured, isError := resultOf(t, mustDispatch(t, g, ctx, appConsumer(), call(appmcp.InventoryToolName, `{"brief":true}`)))
	require.False(t, isError)
	assert.EqualValues(t, 2, structured["callable_tools"])

	_, structured, isError = resultOf(t, mustDispatch(t, g, ctx, appConsumer(), call("trustgate_connect_github", `{}`)))
	require.False(t, isError)
	assert.Contains(t, structured["connect_url"], "/connect?ticket=tk")
}

func mustDispatch(t *testing.T, g *mcphttp.RPCGateway, ctx context.Context, rc *appconsumer.RoutableConsumer, params json.RawMessage) any {
	t.Helper()
	result, err := g.DispatchWithBaseURL(ctx, rc, "https://mcp.example.com", "tools/call", params)
	require.NoError(t, err)
	return result
}

// The overview names every server, what state it is in and, for one the user
// can fix, the call that fixes it.
func TestConsolidated_SearchOverview(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ToolInventory(mock.Anything, mock.Anything).Return(linearSurface(), nil).Once()
	g := appGateway(t, composer, nil)

	text, structured, isError := resultOf(t, mustDispatch(t, g, newClientCtx(), appConsumer(), call(appmcp.SearchToolName, `{}`)))
	require.False(t, isError)
	servers := structured["servers"].([]any)
	require.Len(t, servers, 2)
	github := servers[1].(map[string]any)
	assert.Equal(t, appmcp.InventoryStateNeedsConnect, github["state"])
	assert.Equal(t, map[string]any{
		"tool":      appmcp.AccessToolName,
		"arguments": map[string]any{"action": "connect", "target": "github"},
	}, github["next"])
	assert.Contains(t, text, appmcp.AccessToolName)
	assert.NotContains(t, text, appmcp.InventoryToolName, "the overview never sends a new client to an earlier tool")
	_, hasInstallable := structured["installable"]
	assert.False(t, hasInstallable, "an application cannot install, so it is offered nothing to install")
}

// A search ranks the user's tools; a listing without a query returns every
// one of them — the same set tools/list serves — so a ranking that misses can
// always be worked round.
func TestConsolidated_SearchRanksAndTheListingIsComplete(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ToolInventory(mock.Anything, mock.Anything).Return(linearSurface(), nil).Times(2)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return(linearUpstreamTools(t), nil).Once()
	g := appGateway(t, composer, nil)
	ctx := newClientCtx()

	_, structured, _ := resultOf(t, mustDispatch(t, g, ctx, appConsumer(), call(appmcp.SearchToolName, `{"query":"add a comment to an issue"}`)))
	results := structured["results"].([]any)
	require.NotEmpty(t, results)
	top := results[0].(map[string]any)
	assert.Equal(t, "linear_save_comment", top["name"])
	assert.Equal(t, appmcp.ToolRiskAdditive, top["risk"])
	assert.Equal(t, "linear_save_comment(args: { issueId: string; body: string }): Promise<unknown>", top["signature"])

	_, structured, _ = resultOf(t, mustDispatch(t, g, ctx, appConsumer(), call(appmcp.SearchToolName, `{"kind":"tool"}`)))
	var browsed []string
	for _, r := range structured["results"].([]any) {
		browsed = append(browsed, r.(map[string]any)["name"].(string))
	}
	listed, err := g.Dispatch(ctx, appConsumer(), "tools/list", nil)
	require.NoError(t, err)
	var served []string
	for _, name := range listedNames(t, listed) {
		if !appmcp.IsConsolidatedToolName(name) {
			served = append(served, name)
		}
	}
	sort.Strings(browsed)
	sort.Strings(served)
	assert.Equal(t, served, browsed)
}

// A name that is not on the surface answers with the closest ones that are.
func TestConsolidated_SearchByUnknownNameSuggests(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ToolInventory(mock.Anything, mock.Anything).Return(linearSurface(), nil).Once()
	g := appGateway(t, composer, nil)

	_, structured, _ := resultOf(t, mustDispatch(t, g, newClientCtx(), appConsumer(), call(appmcp.SearchToolName, `{"name":"linear_comment"}`)))
	assert.Equal(t, false, structured["found"])
	assert.Contains(t, structured["suggestions"], "linear_save_comment")
}

// trustgate_call runs the named tool exactly as a direct call, and Activity
// records the tool that ran.
func TestConsolidated_CallRunsTheToolAndActivityNamesIt(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	var forwarded json.RawMessage
	target := expectResolve(composer, "linear_save_comment")
	composer.EXPECT().Invoke(mock.Anything, mock.Anything, target, mock.Anything).
		Run(func(_ context.Context, _ *appconsumer.RoutableConsumer, _ *appmcp.ResolvedTool, args json.RawMessage) {
			forwarded = args
		}).
		Return(json.RawMessage(`{"content":[{"type":"text","text":"commented"}]}`), nil).Once()
	g := appGateway(t, composer, nil)

	rt := trace.New("t-consolidated-call", trace.Metadata{Kind: events.KindMCP})
	ctx := trace.NewContext(newClientCtx(), rt)
	text, _, _ := resultOf(t, mustDispatch(t, g, ctx, appConsumer(),
		call(appmcp.GatewayCallToolName, `{"tool":"linear_save_comment","arguments":{"issueId":"ENG-1","body":"hi"}}`)))

	assert.Equal(t, "commented", text)
	assert.JSONEq(t, `{"issueId":"ENG-1","body":"hi"}`, string(forwarded))
	attrs, ok := rt.Spans()[0].MCPAttrsCopy()
	require.True(t, ok)
	assert.Equal(t, "linear_save_comment", attrs.Tool)
	assert.False(t, rt.IsMetaTool(), "a call that ran a tool is that tool's call")
}

func TestConsolidated_CallRefusesAgentsOffTheStore(t *testing.T) {
	t.Parallel()
	g := appGateway(t, mocks.NewComposer(t), nil)
	_, structured, isError := resultOf(t, mustDispatch(t, g, newClientCtx(), appConsumer(),
		call(appmcp.GatewayCallToolName, `{"agent":"research","message":"hi"}`)))
	assert.True(t, isError)
	assert.Equal(t, "not_available", structured["error"])
}

// On an application, connect gives the link for the server's provider.
func TestConsolidated_AccessConnectGivesTheLink(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ToolInventory(mock.Anything, mock.Anything).Return(linearSurface(), nil).Once()
	g := appGateway(t, composer, []appoauth.ProviderStatus{{Provider: "github"}})

	_, structured, isError := resultOf(t, mustDispatch(t, g, newClientCtx(), appConsumer(),
		call(appmcp.AccessToolName, `{"action":"connect","target":"GitHub"}`)))
	require.False(t, isError)
	assert.Equal(t, "link", structured["status"])
	assert.Contains(t, structured["connect_url"], "/connect?ticket=tk")
}

func TestConsolidated_AccessConnectOnAConnectedServer(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ToolInventory(mock.Anything, mock.Anything).Return(linearSurface(), nil).Once()
	g := appGateway(t, composer, nil)

	_, structured, isError := resultOf(t, mustDispatch(t, g, newClientCtx(), appConsumer(),
		call(appmcp.AccessToolName, `{"action":"connect","target":"linear"}`)))
	require.False(t, isError)
	assert.Equal(t, "connected", structured["status"])
}

// An application cannot install: the action is refused with what it can do.
func TestConsolidated_AccessOffersAnApplicationOnlyConnect(t *testing.T) {
	t.Parallel()
	g := appGateway(t, mocks.NewComposer(t), nil)
	_, structured, isError := resultOf(t, mustDispatch(t, g, newClientCtx(), appConsumer(),
		call(appmcp.AccessToolName, `{"action":"install","target":"com.notion/mcp"}`)))
	assert.True(t, isError)
	assert.Equal(t, []any{"connect"}, structured["actions"])
}

// A toolkit that names no tool exposes nothing, the gateway's tools included.
func TestConsolidated_DenyAllToolkitGetsNoGatewayTools(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return(nil, nil).Once()
	g := appGateway(t, composer, nil)
	rc := appConsumer()
	rc.Consumer.MCP = &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{}}

	listed, err := g.Dispatch(newClientCtx(), rc, "tools/list", nil)
	require.NoError(t, err)
	assert.Empty(t, listedNames(t, listed))
	_, err = g.DispatchWithBaseURL(newClientCtx(), rc, "https://mcp.example.com", "tools/call", call(appmcp.SearchToolName, `{}`))
	var denied *appmcp.ToolNotPermittedError
	require.ErrorAs(t, err, &denied)
}

// fakeStoreTool stands in for the Store tool: it records what it was asked
// and answers what the test says.
type fakeStoreTool struct {
	names   []string
	calls   []storeCallRecord
	answers map[string]json.RawMessage
	errs    map[string]error
}

type storeCallRecord struct {
	name string
	args map[string]any
}

func (f *fakeStoreTool) Definitions(context.Context, *appconsumer.RoutableConsumer) []appmcp.Tool {
	out := make([]appmcp.Tool, 0, len(f.names))
	for _, name := range f.names {
		out = append(out, appmcp.Tool{Name: name})
	}
	return out
}

func (f *fakeStoreTool) Handles(name string) bool {
	for _, n := range f.names {
		if n == name {
			return true
		}
	}
	return false
}

func (f *fakeStoreTool) Call(_ context.Context, _ *appconsumer.RoutableConsumer, _, name string, arguments json.RawMessage) (json.RawMessage, error) {
	var args map[string]any
	_ = json.Unmarshal(arguments, &args)
	f.calls = append(f.calls, storeCallRecord{name: name, args: args})
	if err := f.errs[name]; err != nil {
		return nil, err
	}
	return f.answers[name], nil
}

func newFakeStore() *fakeStoreTool {
	return &fakeStoreTool{
		names: []string{
			appmcp.StoreSearchToolName, appmcp.StoreInstallToolName, appmcp.StoreUninstallToolName,
			appmcp.StorePersonalKeyToolName, appmcp.StoreModelsToolName, appmcp.StoreRequestModelsToolName,
		},
		answers: map[string]json.RawMessage{},
		errs:    map[string]error{},
	}
}

func storeGateway(t *testing.T, composer *mocks.Composer, store *fakeStoreTool) *mcphttp.RPCGateway {
	t.Helper()
	inventory, err := appmcp.NewInventoryTool(composer, nil)
	require.NoError(t, err)
	return mcphttp.NewRPCGatewayWithMetaTools(composer, noopRunner(), nil, nil, store).WithInventoryTool(inventory)
}

// The Store offers the same three tools as an application; what differs is
// what they can do there.
func TestConsolidated_StoreIsOfferedTheSameThreeTools(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return(nil, nil).Once()
	g := storeGateway(t, composer, newFakeStore())

	listed, err := g.Dispatch(newClientCtx(), storeConsumer(), "tools/list", nil)
	require.NoError(t, err)
	tools := listed.(map[string]any)["tools"].([]appmcp.Tool)
	assert.Equal(t, []string{appmcp.SearchToolName, appmcp.GatewayCallToolName, appmcp.AccessToolName}, toolNames(tools))
	raw, err := json.Marshal(tools[2])
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"enum":["install","uninstall","connect","key","request"]`)
}

// install lands on the Store's own install with the arguments renamed, and
// its answer comes back with what happened and the earlier tools' names
// rewritten.
func TestConsolidated_AccessInstallUsesTheStoreInstall(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	store.answers[appmcp.StoreInstallToolName] = json.RawMessage(`{"content":[{"type":"text","text":"Installed Notion. Its tools may be missing from your list: use trustgate_list_tools and trustgate_call_tool."}],"structuredContent":{"code":"com.notion/mcp","already_installed":false}}`)
	g := storeGateway(t, mocks.NewComposer(t), store)

	text, structured, isError := resultOf(t, mustDispatch(t, g, newClientCtx(), storeConsumer(),
		call(appmcp.AccessToolName, `{"action":"install","target":"com.notion/mcp","registry_id":"reg-1","config":{"instance":"acme"}}`)))
	require.False(t, isError)
	require.Len(t, store.calls, 1)
	assert.Equal(t, appmcp.StoreInstallToolName, store.calls[0].name)
	assert.Equal(t, map[string]any{"code": "com.notion/mcp", "instance": "reg-1", "config": map[string]any{"instance": "acme"}}, store.calls[0].args)
	assert.Equal(t, "installed", structured["status"])
	assert.Contains(t, text, appmcp.SearchToolName)
	assert.NotContains(t, text, appmcp.InventoryToolName)
	assert.NotContains(t, text, appmcp.CallToolName)
}

// A fault the earlier tools return as an opaque internal error comes back as
// a tool error the caller can read.
func TestConsolidated_AccessInstallOnAClosedStoreIsReadable(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	store.errs[appmcp.StoreInstallToolName] = appmcp.ErrStoreInstallDisabled
	g := storeGateway(t, mocks.NewComposer(t), store)

	_, structured, isError := resultOf(t, mustDispatch(t, g, newClientCtx(), storeConsumer(),
		call(appmcp.AccessToolName, `{"action":"install","target":"com.notion/mcp"}`)))
	assert.True(t, isError)
	assert.Equal(t, "store_closed", structured["error"])
}

func TestConsolidated_AccessUninstallAndRequestMapTheirArguments(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	store.answers[appmcp.StoreUninstallToolName] = json.RawMessage(`{"content":[{"type":"text","text":"Uninstalled."}],"structuredContent":{"code":"com.notion/mcp","uninstalled":true,"was_installed":true}}`)
	store.answers[appmcp.StoreRequestModelsToolName] = json.RawMessage(`{"content":[{"type":"text","text":"Pick one."}],"structuredContent":{"provider":"openai","requires_registry_choice":true}}`)
	g := storeGateway(t, mocks.NewComposer(t), store)
	ctx := newClientCtx()

	_, structured, _ := resultOf(t, mustDispatch(t, g, ctx, storeConsumer(),
		call(appmcp.AccessToolName, `{"action":"uninstall","target":"com.notion/mcp","installation_id":"inst-1"}`)))
	assert.Equal(t, "uninstalled", structured["status"])
	assert.Equal(t, map[string]any{"code": "com.notion/mcp", "instance": "inst-1"}, store.calls[0].args)

	_, structured, _ = resultOf(t, mustDispatch(t, g, ctx, storeConsumer(),
		call(appmcp.AccessToolName, `{"action":"request","target":"openai"}`)))
	assert.Equal(t, "choose_registry", structured["status"])
	assert.Equal(t, map[string]any{"provider": "openai"}, store.calls[1].args)
}

// The personal key that calls the user's models: key hands the page where
// they create, rotate or revoke it, and takes no target. The key is shown to
// them there and never to the model, and the link keeps the field that tells a
// client to put it in front of the person.
func TestConsolidated_AccessKeyGivesThePersonalKeyPage(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	store.answers[appmcp.StorePersonalKeyToolName] = personalKeyAnswer
	g := storeGateway(t, mocks.NewComposer(t), store)

	_, structured, isError := resultOf(t, mustDispatch(t, g, newClientCtx(), storeConsumer(),
		call(appmcp.AccessToolName, `{"action":"key"}`)))
	require.False(t, isError)
	assert.Equal(t, "link", structured["status"])
	assert.Equal(t, "user_confirmation_required", structured["action"])
	assert.Equal(t, "https://gw.example.com/store/mcp/personal-key?ticket=t", structured["personal_key_url"])
	require.Len(t, store.calls, 1)
	assert.Equal(t, appmcp.StorePersonalKeyToolName, store.calls[0].name)
	assert.Empty(t, store.calls[0].args)
}

// connect with target personal_key, the spelling before key existed, still
// opens the same page.
func TestConsolidated_AccessConnectPersonalKeyStillWorks(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	store.answers[appmcp.StorePersonalKeyToolName] = personalKeyAnswer
	g := storeGateway(t, mocks.NewComposer(t), store)

	_, structured, isError := resultOf(t, mustDispatch(t, g, newClientCtx(), storeConsumer(),
		call(appmcp.AccessToolName, `{"action":"connect","target":"personal_key"}`)))
	require.False(t, isError)
	assert.Equal(t, "link", structured["status"])
	assert.Equal(t, appmcp.StorePersonalKeyToolName, store.calls[0].name)
}

// A Store without personal keys does not offer key, and an application never
// does: personal keys belong to the Store.
func TestConsolidated_AccessKeyIsOnlyWhereKeysAre(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	store.names = []string{appmcp.StoreSearchToolName, appmcp.StoreInstallToolName, appmcp.StoreUninstallToolName}
	g := storeGateway(t, mocks.NewComposer(t), store)
	_, structured, isError := resultOf(t, mustDispatch(t, g, newClientCtx(), storeConsumer(),
		call(appmcp.AccessToolName, `{"action":"key"}`)))
	assert.True(t, isError)
	assert.Equal(t, []any{"install", "uninstall", "connect"}, structured["actions"])
	assert.Empty(t, store.calls)

	app := appGateway(t, mocks.NewComposer(t), nil)
	_, structured, isError = resultOf(t, mustDispatch(t, app, newClientCtx(), appConsumer(),
		call(appmcp.AccessToolName, `{"action":"key"}`)))
	assert.True(t, isError)
	assert.Equal(t, []any{"connect"}, structured["actions"])
}

var personalKeyAnswer = json.RawMessage(`{"content":[{"type":"text","text":"Open the link."}],"structuredContent":{"personal_key_url":"https://gw.example.com/store/mcp/personal-key?ticket=t","personal_key_label":"Personal key","action":"user_confirmation_required"}}`)

// The models the user's personal key reaches come from the Store's model
// listing; with no key yet, its answer sends the caller to the consolidated
// tool that gets one, not to a tool missing from its list.
func TestConsolidated_SearchModelsPointsAtTheKeyPage(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	store.answers[appmcp.StoreModelsToolName] = json.RawMessage(`{"content":[{"type":"text","text":"The user has no personal key on this gateway yet, and their models are called with it. Offer trustgate_store_personal_key to get one; then call this again."}],"structuredContent":{"available":true,"has_key":false,"providers":[]}}`)
	g := storeGateway(t, mocks.NewComposer(t), store)

	text, structured, isError := resultOf(t, mustDispatch(t, g, newClientCtx(), storeConsumer(),
		call(appmcp.SearchToolName, `{"kind":"model"}`)))
	require.False(t, isError)
	assert.Equal(t, appmcp.StoreModelsToolName, store.calls[0].name)
	assert.Equal(t, false, structured["has_key"])
	assert.Contains(t, text, `trustgate_access (action "key")`)
	assert.NotContains(t, text, appmcp.StorePersonalKeyToolName)
}

// Searching the catalog lands on the Store's own search, with its text
// pointing at the consolidated tools.
func TestConsolidated_SearchCatalogUsesTheStoreSearch(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	store.answers[appmcp.StoreSearchToolName] = json.RawMessage(`{"content":[{"type":"text","text":"Found 1. Install with trustgate_store_install."}],"structuredContent":{"results":[{"code":"com.notion/mcp","store_state":"available"}],"total":1}}`)
	g := storeGateway(t, mocks.NewComposer(t), store)

	text, structured, _ := resultOf(t, mustDispatch(t, g, newClientCtx(), storeConsumer(),
		call(appmcp.SearchToolName, `{"kind":"catalog","query":"notion"}`)))
	assert.Equal(t, map[string]any{"query": "notion"}, store.calls[0].args)
	assert.EqualValues(t, 1, structured["total"])
	assert.Contains(t, text, appmcp.AccessToolName)
	assert.NotContains(t, text, appmcp.StoreInstallToolName)
}
