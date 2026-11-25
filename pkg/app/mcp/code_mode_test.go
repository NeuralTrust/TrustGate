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
	"sort"
	"strings"
	"sync"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/jsrun"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

func TestMain(m *testing.M) {
	jsrun.Warm()
	m.Run()
}

// scriptedUpstream answers each tool by name and records what was called.
type scriptedUpstream struct {
	*fakeUpstream
	mu      sync.Mutex
	called  []string
	answers map[string]string
}

func (s *scriptedUpstream) CallTool(_ context.Context, name string, _ json.RawMessage) (json.RawMessage, error) {
	s.mu.Lock()
	s.called = append(s.called, name)
	s.mu.Unlock()
	if answer, ok := s.answers[name]; ok {
		return json.RawMessage(answer), nil
	}
	return json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`), nil
}

func (s *scriptedUpstream) calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.called...)
}

type oneUpstreamDialer struct{ up Upstream }

func (d oneUpstreamDialer) Connect(context.Context, Target) (Upstream, error) { return d.up, nil }

func annotatedTool(t *testing.T, name, description string, annotations map[string]any) Tool {
	t.Helper()
	def := map[string]any{"name": name, "description": description, "inputSchema": map[string]any{"type": "object"}}
	if annotations != nil {
		def["annotations"] = annotations
	}
	tool, err := toolFromDefinition(def)
	if err != nil {
		t.Fatalf("tool: %v", err)
	}
	return tool
}

// codeWorld is a dispatcher over one Linear-like server whose tools say
// different things about themselves.
type codeWorld struct {
	d   *RPCDispatcher
	up  *scriptedUpstream
	rc  *appconsumer.RoutableConsumer
	rt  *trace.RequestTrace
	ctx func(mode string) context.Context
	n   func(string) string
}

func newCodeWorld(t *testing.T, executor appplugins.Executor) codeWorld {
	t.Helper()
	reg := mcpRegistry(t, "linear", "https://linear.example.com/mcp")
	reg.MCPTarget.ReadOnlyTools = []string{"get_secret_metadata"}
	readOnly := map[string]any{"readOnlyHint": true}
	up := &scriptedUpstream{
		fakeUpstream: &fakeUpstream{tools: []Tool{
			annotatedTool(t, "list_issues", "List issues", readOnly),
			annotatedTool(t, "list_comments", "List the comments on an issue", readOnly),
			annotatedTool(t, "save_comment", "Add a comment", map[string]any{"readOnlyHint": false, "destructiveHint": false}),
			annotatedTool(t, "web_search", "Search the web", map[string]any{"readOnlyHint": true, "openWorldHint": true}),
			annotatedTool(t, "get_secret_metadata", "Unannotated, vouched for by the admin", nil),
			annotatedTool(t, "export_everything", "Unannotated", nil),
		}},
		answers: map[string]string{
			"list_issues":       `{"content":[{"type":"text","text":"{\"issues\":[{\"id\":\"ENG-1\"},{\"id\":\"ENG-2\"}]}"}]}`,
			"list_comments":     `{"content":[],"structuredContent":{"comments":["first","second"]}}`,
			"save_comment":      `{"content":[{"type":"text","text":"saved"}]}`,
			"export_everything": `{"content":[{"type":"text","text":"denied upstream"}],"isError":true}`,
		},
	}
	composer := newTestComposer(oneUpstreamDialer{up: up})
	inventory, err := NewInventoryTool(composer.(SurfaceInventory), nil)
	if err != nil {
		t.Fatalf("inventory tool: %v", err)
	}
	consumer := &consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: ids.New[ids.GatewayKind](), Type: consumerdomain.TypeMCP, Active: true}
	rt := trace.New("t-code", trace.Metadata{Kind: events.KindMCP})
	return codeWorld{
		d: NewRPCDispatcher(composer, NewPluginRunner(executor, nil), nil, nil, nil).
			WithInventoryTool(inventory).
			WithPrograms(jsrun.New(jsrun.Limits{}, 4)),
		up: up,
		rc: routable(consumer, reg),
		rt: rt,
		ctx: func(mode string) context.Context {
			ctx := identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "ana", Method: identity.MethodOAuth})
			ctx = appgateway.WithGateway(ctx, &gatewaydomain.Gateway{ID: consumer.GatewayID, Metadata: gatewaydomain.WithMCPCodeMode(nil, mode)})
			return trace.NewContext(ctx, rt)
		},
		n: func(name string) string { return namedFor(reg, name) },
	}
}

func (w codeWorld) listed(t *testing.T, mode string) []string {
	t.Helper()
	result, err := w.d.Dispatch(w.ctx(mode), w.rc, "", "tools/list", nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	var names []string
	for _, tool := range result.(map[string]any)["tools"].([]Tool) {
		names = append(names, tool.Name)
	}
	return names
}

// program runs code with tool and returns its structured answer and whether
// it is an error.
func (w codeWorld) program(t *testing.T, mode, tool, code string) (map[string]any, string, bool) {
	t.Helper()
	args, _ := json.Marshal(map[string]string{"code": code})
	params, _ := json.Marshal(map[string]any{"name": tool, "arguments": json.RawMessage(args)})
	result, err := w.d.Dispatch(w.ctx(mode), w.rc, "", "tools/call", params)
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	var envelope struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		StructuredContent map[string]any `json:"structuredContent"`
		IsError           bool           `json:"isError"`
	}
	raw, _ := json.Marshal(result)
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	var text string
	for _, block := range envelope.Content {
		text += block.Text
	}
	return envelope.StructuredContent, text, envelope.IsError
}

func programResultJSON(t *testing.T, structured map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(structured["result"])
	if err != nil {
		t.Fatalf("encode result: %v", err)
	}
	return string(raw)
}

func TestCodeMode_ListedPerGatewayMode(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t, nil)
	has := func(names []string, name string) bool { return containsString(names, name) }
	if names := w.listed(t, gatewaydomain.MCPCodeModeOff); has(names, QueryToolName) || has(names, ExecuteToolName) {
		t.Fatalf("off lists %v", names)
	}
	if names := w.listed(t, gatewaydomain.MCPCodeModeReadOnly); !has(names, QueryToolName) || has(names, ExecuteToolName) {
		t.Fatalf("read_only lists %v", names)
	}
	if names := w.listed(t, gatewaydomain.MCPCodeModeFull); !has(names, QueryToolName) || !has(names, ExecuteToolName) {
		t.Fatalf("full lists %v", names)
	}
	query, err := programDefinition(QueryToolName, jsrun.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if risk, _ := query.Risk(); risk != ToolRiskReadOnly {
		t.Fatalf("trustgate_query risk = %q, want read_only so clients can treat it as such", risk)
	}
	execute, _ := programDefinition(ExecuteToolName, jsrun.DefaultLimits)
	if risk, _ := execute.Risk(); risk != ToolRiskDestructive {
		t.Fatalf("trustgate_execute risk = %q, want destructive so clients ask first", risk)
	}
}

func TestCodeMode_QueryCallsReadOnlyToolsAndReturnsOneResult(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t, nil)
	structured, text, isError := w.program(t, gatewaydomain.MCPCodeModeReadOnly, QueryToolName, `
		const { issues } = await tools.`+w.n("list_issues")+`({ state: "started" });
		const comments = await Promise.all(issues.map(i => tools.`+w.n("list_comments")+`({ issueId: i.id })));
		console.log("issues", issues.length);
		return issues.map((i, k) => ({ id: i.id, comments: comments[k].comments.length }));
	`)
	if isError {
		t.Fatalf("error: %s", text)
	}
	if got := programResultJSON(t, structured); got != `[{"comments":2,"id":"ENG-1"},{"comments":2,"id":"ENG-2"}]` {
		t.Fatalf("result = %s", got)
	}
	if calls := structured["calls"].([]any); len(calls) != 3 {
		t.Fatalf("calls = %v", calls)
	}
	if !strings.Contains(text, "issues 2") {
		t.Fatalf("text = %q, want the logs", text)
	}

	// One span per call, marked as the program's, with its server.
	var programSpans []trace.MCPAttrs
	for _, span := range w.rt.Spans() {
		if attrs, ok := span.MCPAttrsCopy(); ok && attrs.Program == QueryToolName {
			programSpans = append(programSpans, attrs)
		}
	}
	if len(programSpans) != 3 {
		t.Fatalf("program spans = %d, want 3", len(programSpans))
	}
	for _, attrs := range programSpans {
		if attrs.RegistryID == "" || attrs.UpstreamStatus != 200 || attrs.ToolRisk != ToolRiskReadOnly {
			t.Fatalf("span = %+v", attrs)
		}
	}
	if !w.rt.IsMetaTool() {
		t.Fatal("the program's own request is the gateway's; its calls are what count")
	}
}

// A read-only program cannot call a tool that may write, one its server does
// not annotate (unless the admin vouched for it), or one that declares it
// reaches an open world. The refusal is an error the program can catch, and
// the tool is never called.
func TestCodeMode_QueryCallsOnlyToolsThatRead(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t, nil)
	structured, text, isError := w.program(t, gatewaydomain.MCPCodeModeReadOnly, QueryToolName, `
		const out = {};
		for (const name of ["save_comment", "web_search", "export_everything", "get_secret_metadata"]) {
			try { await tools["`+w.n("")+`" + name]({}); out[name] = "called"; }
			catch (e) { out[name] = e.name; }
		}
		return out;
	`)
	if isError {
		t.Fatalf("error: %s", text)
	}
	want := `{"export_everything":"NotAllowedError","get_secret_metadata":"called","save_comment":"NotAllowedError","web_search":"NotAllowedError"}`
	if got := programResultJSON(t, structured); got != want {
		t.Fatalf("result = %s, want %s", got, want)
	}
	if calls := w.up.calls(); len(calls) != 1 || calls[0] != "get_secret_metadata" {
		t.Fatalf("upstream calls = %v, want only the vouched-for tool", calls)
	}
}

func TestCodeMode_ExecuteCallsAnyToolAndOnlyWhenFull(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t, nil)
	_, text, isError := w.program(t, gatewaydomain.MCPCodeModeReadOnly, ExecuteToolName, `return 1;`)
	if !isError || !strings.Contains(text, QueryToolName) {
		t.Fatalf("execute on a read-only gateway: %q (error %v)", text, isError)
	}
	structured, text, isError := w.program(t, gatewaydomain.MCPCodeModeFull, ExecuteToolName, `
		const saved = await tools.`+w.n("save_comment")+`({ issueId: "ENG-1", body: "done" });
		let failed = null;
		try { await tools.`+w.n("export_everything")+`({}); } catch (e) { failed = e.name + ": " + e.message; }
		return { saved, failed };
	`)
	if isError {
		t.Fatalf("error: %s", text)
	}
	if got := programResultJSON(t, structured); got != `{"failed":"ToolError: denied upstream","saved":"saved"}` {
		t.Fatalf("result = %s", got)
	}
	if calls := w.up.calls(); strings.Join(calls, ",") != "save_comment,export_everything" {
		t.Fatalf("upstream calls = %v", calls)
	}
	_, text, isError = w.program(t, gatewaydomain.MCPCodeModeOff, QueryToolName, `return 1;`)
	if !isError || !strings.Contains(text, "not turned on") {
		t.Fatalf("query with Code Mode off: %q", text)
	}
}

func TestCodeMode_AnUnknownToolNamesTheClosest(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t, nil)
	structured, _, _ := w.program(t, gatewaydomain.MCPCodeModeReadOnly, QueryToolName, `
		try { await tools.linear_list_issue({}); } catch (e) { return e.name + " " + e.message; }
	`)
	got := programResultJSON(t, structured)
	if !strings.Contains(got, "NotFoundError") || !strings.Contains(got, w.n("list_issues")) {
		t.Fatalf("result = %s", got)
	}
}

func TestCodeMode_AFailedProgramSaysWhyAndWhatItCalled(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t, nil)
	structured, text, isError := w.program(t, gatewaydomain.MCPCodeModeReadOnly, QueryToolName, `
		await tools.`+w.n("list_issues")+`({});
		console.log("about to fail");
		throw new Error("no issue is blocked");
	`)
	if !isError {
		t.Fatal("a program that throws is a tool error")
	}
	for _, want := range []string{"no issue is blocked", w.n("list_issues"), "about to fail", "Fix the program"} {
		if !strings.Contains(text, want) {
			t.Fatalf("text %q lacks %q", text, want)
		}
	}
	if structured["error"] != string(jsrun.KindThrown) {
		t.Fatalf("structured = %v", structured)
	}
	_, text, isError = w.program(t, gatewaydomain.MCPCodeModeReadOnly, QueryToolName, `return [1, 2`)
	if !isError || !strings.Contains(text, "SyntaxError") {
		t.Fatalf("syntax error: %q", text)
	}
}

// guardExecutor masks any response whose body carries "SECRET".
type guardExecutor struct{}

func (guardExecutor) RunStage(_ context.Context, in appplugins.StageInput) (*appplugins.StageOutcome, error) {
	if in.Stage != policy.StagePreResponse || in.Response == nil || !strings.Contains(string(in.Response.Body), "SECRET") {
		return nil, nil
	}
	return &appplugins.StageOutcome{
		ShortCircuit: true,
		StatusCode:   200,
		Body:         []byte(`{"content":[{"type":"text","text":"[masked]"}]}`),
	}, nil
}

// Each call's result passed the response policies on its own; what the
// program builds from them passes them again, so joining two clean halves
// cannot smuggle out what a guard would have masked.
func TestCodeMode_TheProgramsAnswerPassesTheResponsePolicies(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t, guardExecutor{})
	w.rc.Policies = []*policy.Policy{{Enabled: true, Mode: policy.ModeEnforce, Stages: []policy.Stage{policy.StagePreResponse}}}
	_, text, isError := w.program(t, gatewaydomain.MCPCodeModeReadOnly, QueryToolName, `
		await tools.`+w.n("list_issues")+`({});
		return "SEC" + "RET";
	`)
	if isError || text != "[masked]" {
		t.Fatalf("answer = %q (error %v), want the masked one", text, isError)
	}
}

// A program counts as its calls in the search funnel too: its first call
// after a search is that search's follow-up.
func TestCodeMode_ProgramCallsFollowASearch(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t, nil)
	key := callerKey(w.ctx(gatewaydomain.MCPCodeModeReadOnly), w.rc)
	w.d.searchStats.recent.remember(key, []string{w.n("list_issues")}, 0)
	w.program(t, gatewaydomain.MCPCodeModeReadOnly, QueryToolName, `return await tools.`+w.n("list_issues")+`({});`)
	if _, pending := w.d.searchStats.recent.take(key); pending {
		t.Fatal("the program's call did not count as the search's follow-up")
	}
}

// A consent the user must give ends the program with the error a direct call
// would have got.
func TestCodeMode_ConsentEndsTheProgram(t *testing.T) {
	t.Parallel()
	res, err := invokeFailure(&ConsentRequiredError{Provider: "linear"})
	var consent *ConsentRequiredError
	if !errors.As(err, &consent) || res.Err != nil {
		t.Fatalf("invokeFailure = %+v, %v", res, err)
	}
	_, err = invokeFailure(&RPCError{Code: CodeRateLimited, Message: "slow down"})
	if err == nil {
		t.Fatal("a rate limit ends the program")
	}
	res, err = invokeFailure(&RPCError{Code: CodePolicyBlocked, Message: "pii"})
	if err != nil || res.Err == nil || res.Err.Name != "PolicyError" {
		t.Fatalf("a policy refusal is an error the program can catch: %+v, %v", res, err)
	}
}

func TestProgramValue(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		`{"content":[],"structuredContent":{"a":1}}`:                             `{"a":1}`,
		`{"content":[{"type":"text","text":"{\"b\":2}"}]}`:                       `{"b":2}`,
		`{"content":[{"type":"text","text":"plain words"}]}`:                     `"plain words"`,
		`{"content":[{"type":"text","text":"one"},{"type":"image","data":"…"}]}`: `["one",{"omitted":true,"type":"image"}]`,
	} {
		res := programValue(json.RawMessage(in))
		if res.Err != nil {
			t.Fatalf("%s: error %v", in, res.Err)
		}
		var got any
		_ = json.Unmarshal(res.Value, &got)
		normalized, _ := json.Marshal(got)
		if string(normalized) != want {
			t.Fatalf("%s: value = %s, want %s", in, normalized, want)
		}
	}
	res := programValue(json.RawMessage(`{"content":[{"type":"text","text":"nope"}],"isError":true}`))
	if res.Err == nil || res.Err.Message != "nope" {
		t.Fatalf("isError = %+v", res)
	}
}

// callTool makes one tools/call and returns the result's text and whether it
// is an error.
func (w codeWorld) callTool(t *testing.T, mode, name string, arguments any) (string, bool) {
	t.Helper()
	params, _ := json.Marshal(map[string]any{"name": name, "arguments": arguments})
	result, err := w.d.Dispatch(w.ctx(mode), w.rc, "", "tools/call", params)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	raw, _ := json.Marshal(result)
	var envelope struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	var text string
	for _, block := range envelope.Content {
		text += block.Text
	}
	return text, envelope.IsError
}

// A client that kept the tool list it fetched before Code Mode was turned on
// has no trustgate_query of its own; both call-throughs run one for it, under
// the gateway's mode like a direct call.
func TestCodeMode_ProgramsRunThroughTheCallThroughs(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t, nil)
	code := map[string]any{"code": `return (await tools.` + w.n("list_issues") + `({})).issues.length;`}
	for _, via := range []struct {
		name string
		args map[string]any
	}{
		{CallToolName, map[string]any{"name": QueryToolName, "arguments": code}},
		{GatewayCallToolName, map[string]any{"tool": QueryToolName, "arguments": code}},
	} {
		text, isError := w.callTool(t, gatewaydomain.MCPCodeModeReadOnly, via.name, via.args)
		if isError || !strings.HasPrefix(text, "2") {
			t.Fatalf("through %s: %q (error %v), want the program's result", via.name, text, isError)
		}
		text, isError = w.callTool(t, gatewaydomain.MCPCodeModeOff, via.name, via.args)
		if !isError || !strings.Contains(text, "not turned on") {
			t.Fatalf("through %s with Code Mode off: %q", via.name, text)
		}
	}
	// Other gateway tools are still refused through a call-through, without
	// claiming the client has them.
	text, isError := w.callTool(t, gatewaydomain.MCPCodeModeReadOnly, CallToolName, map[string]any{"name": SearchToolName})
	if !isError || strings.Contains(text, "already in your tool list") {
		t.Fatalf("gateway tool through %s: %q", CallToolName, text)
	}
}

// The earlier inventory tool's answer is where a client on the earlier tools
// learns that programs exist and how to run one.
func TestCodeMode_TheEarlierInventoryTellsHowToRunAProgram(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t, nil)
	text, _ := w.callTool(t, gatewaydomain.MCPCodeModeReadOnly, InventoryToolName, map[string]any{"brief": true})
	if !strings.Contains(text, `"name": "`+QueryToolName+`"`) || !strings.Contains(text, CallToolName) || strings.Contains(text, ExecuteToolName) {
		t.Fatalf("read_only inventory: %q", text)
	}
	text, _ = w.callTool(t, gatewaydomain.MCPCodeModeFull, InventoryToolName, map[string]any{})
	if !strings.Contains(text, ExecuteToolName) {
		t.Fatalf("full inventory: %q", text)
	}
	text, _ = w.callTool(t, gatewaydomain.MCPCodeModeOff, InventoryToolName, map[string]any{})
	if strings.Contains(text, QueryToolName) {
		t.Fatalf("off inventory mentions programs: %q", text)
	}
}

// A gateway that lists only its own tools lists no upstream tool; the user's
// are still found by search and reached by a direct call, trustgate_call or a
// program.
func TestToolListing_GatewayToolsOnly(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t, nil)
	listingCtx := func(mode string) context.Context {
		ctx := w.ctx(mode)
		gw, _ := appgateway.FromContext(ctx)
		gw.Metadata = gatewaydomain.WithMCPToolListing(gw.Metadata, gatewaydomain.MCPToolListingGateway)
		return ctx
	}
	result, err := w.d.Dispatch(listingCtx(gatewaydomain.MCPCodeModeReadOnly), w.rc, "", "tools/list", nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	var names []string
	for _, tool := range result.(map[string]any)["tools"].([]Tool) {
		names = append(names, tool.Name)
	}
	var want []string
	for _, name := range w.listed(t, gatewaydomain.MCPCodeModeReadOnly) {
		if strings.HasPrefix(name, "trustgate_") {
			want = append(want, name)
		}
	}
	sort.Strings(names)
	sort.Strings(want)
	if len(want) == 0 || strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("listed %v, want only the gateway's tools %v", names, want)
	}
	// A direct call to a tool the client knows still reaches it.
	params, _ := json.Marshal(map[string]any{"name": w.n("list_issues"), "arguments": map[string]any{}})
	if _, err := w.d.Dispatch(listingCtx(gatewaydomain.MCPCodeModeOff), w.rc, "", "tools/call", params); err != nil {
		t.Fatalf("direct call: %v", err)
	}
	if got := ToolListingInstructions(listingCtx(gatewaydomain.MCPCodeModeOff), w.rc); !strings.Contains(got, SearchToolName) {
		t.Fatalf("instructions = %q", got)
	}
	if got := ToolListingInstructions(w.ctx(gatewaydomain.MCPCodeModeOff), w.rc); got != "" {
		t.Fatalf("a gateway that lists everything says %q", got)
	}
}

// A program's request is attributed, in Activity, to the server its calls
// went to.
func TestCodeMode_TheProgramsRequestNamesItsServer(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t, nil)
	outer := w.rt.StartSpan(trace.SpanMCP, "tools/call")
	ctx := trace.NewSpanContext(w.ctx(gatewaydomain.MCPCodeModeReadOnly), outer)
	args, _ := json.Marshal(map[string]string{"code": `await tools.` + w.n("list_issues") + `({}); return 1;`})
	params, _ := json.Marshal(map[string]any{"name": QueryToolName, "arguments": json.RawMessage(args)})
	if _, err := w.d.Dispatch(ctx, w.rc, "", "tools/call", params); err != nil {
		t.Fatalf("program: %v", err)
	}
	attrs, _ := outer.MCPAttrsCopy()
	if attrs.ServerName != "linear" || attrs.RegistryID == "" {
		t.Fatalf("program span = %+v, want the linear server", attrs)
	}
}
