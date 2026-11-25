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

// The world the Code Mode agent eval (code_mode_agent_eval_test.go, behind
// the agenteval tag) runs in: fake Linear, GitHub and Calendar servers with
// fixed data, the tasks and what their answers must say. The reference
// programs below solve every task through trustgate_query, so this file is
// also an end-to-end test of Code Mode over several servers, run in CI.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/jsrun"
)

// evalTask is one request and what its answer must say.
type evalTask struct {
	Name string
	// Prompt is what the user asks.
	Prompt string
	// Want are substrings the final answer must contain, case-insensitive.
	Want []string
	// MultiStep marks a task that takes several calls or a computation over
	// a call's result: the kind Code Mode is for.
	MultiStep bool
}

var evalTasks = []evalTask{
	{Name: "uncommented-issues", MultiStep: true,
		Prompt: "How many of my started Linear issues have no comments yet? Answer with the number and their ids.",
		Want:   []string{"2", "ENG-103", "ENG-106"}},
	{Name: "most-commented", MultiStep: true,
		Prompt: "Which of my started Linear issues has the most comments? Give me its id.",
		Want:   []string{"ENG-104"}},
	{Name: "last-commenter", MultiStep: true,
		Prompt: "For each of my started Linear issues that has comments, who wrote the last comment?",
		Want:   []string{"ENG-101", "marta", "ENG-104", "ana"}},
	{Name: "urgent-points", MultiStep: true,
		Prompt: "Add up the estimate points of all urgent Linear issues, whoever they are assigned to.",
		Want:   []string{"13"}},
	{Name: "stale-payments-prs", MultiStep: true,
		Prompt: "Which open GitHub pull requests touch the payments service and were opened more than 7 days ago (today is 2026-11-25)? Give their numbers.",
		Want:   []string{"#41", "#57"}},
	{Name: "pr-reviewers", MultiStep: true,
		Prompt: "Who is asked to review the most open GitHub pull requests? Look at each one's details.",
		Want:   []string{"jon"}},
	{Name: "overlapping-meetings", MultiStep: true,
		Prompt: "Do any of my calendar events on 2026-11-26 overlap? Name the ones that do.",
		Want:   []string{"Design review", "Vendor call"}},
	{Name: "issue-title", MultiStep: false,
		Prompt: "What is the title of Linear issue ENG-102?",
		Want:   []string{"Rotate the signing keys"}},
	{Name: "one-pr", MultiStep: false,
		Prompt: "Who opened GitHub pull request #57?",
		Want:   []string{"lucia"}},
	{Name: "cross-server", MultiStep: true,
		Prompt: "Which open GitHub pull requests mention a Linear issue in their title, and what is the state of that issue?",
		Want:   []string{"#41", "ENG-101", "started", "#63", "ENG-105", "done"}},
}

// The fixed data the fake servers serve.
var (
	evalIssues = []map[string]any{
		{"id": "ENG-101", "title": "Payments retry storm", "state": "started", "assignee": "me", "priority": "urgent", "estimate": 5},
		{"id": "ENG-102", "title": "Rotate the signing keys", "state": "started", "assignee": "me", "priority": "high", "estimate": 3},
		{"id": "ENG-103", "title": "Flaky login test", "state": "started", "assignee": "me", "priority": "low", "estimate": 1},
		{"id": "ENG-104", "title": "Checkout latency regression", "state": "started", "assignee": "me", "priority": "urgent", "estimate": 8},
		{"id": "ENG-105", "title": "Webhook signature check", "state": "done", "assignee": "me", "priority": "medium", "estimate": 2},
		{"id": "ENG-106", "title": "Docs for the new API", "state": "started", "assignee": "me", "priority": "low", "estimate": 2},
		{"id": "ENG-107", "title": "Refund export", "state": "backlog", "assignee": "jon", "priority": "medium", "estimate": 3},
	}
	evalComments = map[string][]map[string]any{
		"ENG-101": {{"author": "jon", "body": "seeing it again"}, {"author": "marta", "body": "fix deployed"}},
		"ENG-102": {{"author": "ana", "body": "keys rotated in staging"}},
		"ENG-104": {{"author": "jon", "body": "p95 up"}, {"author": "marta", "body": "bisecting"}, {"author": "ana", "body": "found it"}},
		"ENG-105": {{"author": "me", "body": "shipped"}},
	}
	evalPRs = []map[string]any{
		{"number": 41, "title": "ENG-101: back off payment retries", "state": "open", "author": "marta", "created_at": "2026-11-10", "files": []string{"services/payments/retry.go"}, "reviewers": []string{"jon", "ana"}},
		{"number": 57, "title": "Payments: idempotency keys", "state": "open", "author": "lucia", "created_at": "2026-11-12", "files": []string{"services/payments/keys.go"}, "reviewers": []string{"jon"}},
		{"number": 60, "title": "Payments: log refunds", "state": "open", "author": "jon", "created_at": "2026-11-22", "files": []string{"services/payments/refunds.go"}, "reviewers": []string{"ana"}},
		{"number": 63, "title": "ENG-105 follow-up: verify webhook timestamps", "state": "open", "author": "ana", "created_at": "2026-11-20", "files": []string{"services/webhooks/verify.go"}, "reviewers": []string{"jon"}},
		{"number": 64, "title": "Docs typo", "state": "open", "author": "me", "created_at": "2026-11-01", "files": []string{"docs/readme.md"}, "reviewers": []string{"marta"}},
		{"number": 30, "title": "Payments: old cleanup", "state": "closed", "author": "jon", "created_at": "2026-10-01", "files": []string{"services/payments/old.go"}, "reviewers": []string{"ana"}},
	}
	evalEvents = []map[string]any{
		{"title": "Standup", "start": "2026-11-26T09:00", "end": "2026-11-26T09:15"},
		{"title": "Design review", "start": "2026-11-26T10:00", "end": "2026-11-26T11:00"},
		{"title": "Vendor call", "start": "2026-11-26T10:30", "end": "2026-11-26T11:15"},
		{"title": "Lunch", "start": "2026-11-26T13:00", "end": "2026-11-26T14:00"},
		{"title": "1:1", "start": "2026-11-27T10:00", "end": "2026-11-27T10:30"},
	}
)

// funcUpstream answers every call with a function of its name and arguments.
type funcUpstream struct {
	*fakeUpstream
	answer func(name string, args map[string]any) any
}

func (f *funcUpstream) CallTool(_ context.Context, name string, arguments json.RawMessage) (json.RawMessage, error) {
	var args map[string]any
	_ = json.Unmarshal(arguments, &args)
	value := f.answer(name, args)
	if msg, failed := value.(error); failed {
		return json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": msg.Error()}}, "isError": true})
	}
	text, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	// Like most servers, they answer JSON as text, without an output schema.
	return json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": string(text)}}})
}

type urlDialer map[string]Upstream

func (d urlDialer) Connect(_ context.Context, target Target) (Upstream, error) {
	up, ok := d[target.URL]
	if !ok {
		return nil, fmt.Errorf("unknown target %s", target.URL)
	}
	return up, nil
}

func evalTool(t *testing.T, name, description string, properties map[string]any, readOnly bool) Tool {
	t.Helper()
	schema := map[string]any{"type": "object", "properties": properties}
	tool, err := toolFromDefinition(map[string]any{
		"name": name, "description": description, "inputSchema": schema,
		"annotations": map[string]any{"readOnlyHint": readOnly},
	})
	if err != nil {
		t.Fatal(err)
	}
	return tool
}

func str(args map[string]any, key string) string { s, _ := args[key].(string); return s }

type evalWorld struct {
	d  *RPCDispatcher
	rc *appconsumer.RoutableConsumer
}

func newEvalWorld(t *testing.T) evalWorld {
	t.Helper()
	strProp := map[string]any{"type": "string"}
	numProp := map[string]any{"type": "number"}
	linear := &funcUpstream{fakeUpstream: &fakeUpstream{tools: []Tool{
		evalTool(t, "list_issues", "List Linear issues, filtered by state, assignee or priority. Returns {issues: [{id, title, state, assignee, priority, estimate}]}.", map[string]any{"state": strProp, "assignee": strProp, "priority": strProp}, true),
		evalTool(t, "get_issue", "Get one Linear issue by id. Returns {id, title, state, assignee, priority, estimate}.", map[string]any{"id": strProp}, true),
		evalTool(t, "list_comments", "List the comments on a Linear issue, oldest first. Returns {comments: [{author, body}]}.", map[string]any{"issueId": strProp}, true),
		evalTool(t, "save_comment", "Add a comment to a Linear issue.", map[string]any{"issueId": strProp, "body": strProp}, false),
	}}, answer: func(name string, args map[string]any) any {
		switch name {
		case "list_issues":
			var out []map[string]any
			for _, issue := range evalIssues {
				if v := str(args, "state"); v != "" && issue["state"] != v {
					continue
				}
				if v := str(args, "assignee"); v != "" && issue["assignee"] != v {
					continue
				}
				if v := str(args, "priority"); v != "" && issue["priority"] != v {
					continue
				}
				out = append(out, issue)
			}
			return map[string]any{"issues": out}
		case "get_issue":
			for _, issue := range evalIssues {
				if issue["id"] == str(args, "id") {
					return issue
				}
			}
			return fmt.Errorf("no issue %q", str(args, "id"))
		case "list_comments":
			comments := evalComments[str(args, "issueId")]
			if comments == nil {
				comments = []map[string]any{}
			}
			return map[string]any{"comments": comments}
		case "save_comment":
			return map[string]any{"ok": true}
		}
		return fmt.Errorf("unknown tool %s", name)
	}}
	github := &funcUpstream{fakeUpstream: &fakeUpstream{tools: []Tool{
		evalTool(t, "list_pull_requests", "List GitHub pull requests by state (open, closed). Returns {pull_requests: [{number, title, state, author, created_at}]}.", map[string]any{"state": strProp}, true),
		evalTool(t, "get_pull_request", "Get one GitHub pull request with the files it changes and its requested reviewers.", map[string]any{"number": numProp}, true),
	}}, answer: func(name string, args map[string]any) any {
		switch name {
		case "list_pull_requests":
			var out []map[string]any
			for _, pr := range evalPRs {
				if v := str(args, "state"); v != "" && pr["state"] != v {
					continue
				}
				out = append(out, map[string]any{"number": pr["number"], "title": pr["title"], "state": pr["state"], "author": pr["author"], "created_at": pr["created_at"]})
			}
			return map[string]any{"pull_requests": out}
		case "get_pull_request":
			n, _ := args["number"].(float64)
			for _, pr := range evalPRs {
				if pr["number"] == int(n) {
					return pr
				}
			}
			return fmt.Errorf("no pull request #%v", args["number"])
		}
		return fmt.Errorf("unknown tool %s", name)
	}}
	calendar := &funcUpstream{fakeUpstream: &fakeUpstream{tools: []Tool{
		evalTool(t, "list_events", "List calendar events on a day (YYYY-MM-DD). Returns {events: [{title, start, end}]}.", map[string]any{"day": strProp}, true),
	}}, answer: func(_ string, args map[string]any) any {
		var out []map[string]any
		for _, event := range evalEvents {
			if strings.HasPrefix(event["start"].(string), str(args, "day")) {
				out = append(out, event)
			}
		}
		return map[string]any{"events": out}
	}}
	// Catalog codes give the tools the names they have in production:
	// linear_list_issues, github_get_pull_request, calendar_list_events.
	regs := []*registrydomain.Registry{
		mcpRegistry(t, "Linear", "https://linear.example.com/mcp"),
		mcpRegistry(t, "GitHub", "https://github.example.com/mcp"),
		mcpRegistry(t, "Calendar", "https://calendar.example.com/mcp"),
	}
	for i, code := range []string{"app.linear/mcp", "com.github/mcp", "com.calendar/mcp"} {
		regs[i].MCPTarget.Code = code
	}
	composer := newTestComposer(urlDialer{
		"https://linear.example.com/mcp":   linear,
		"https://github.example.com/mcp":   github,
		"https://calendar.example.com/mcp": calendar,
	})
	inventory, err := NewInventoryTool(composer.(SurfaceInventory), nil)
	if err != nil {
		t.Fatal(err)
	}
	consumer := &consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: ids.New[ids.GatewayKind](), Type: consumerdomain.TypeMCP, Active: true}
	return evalWorld{
		d: NewRPCDispatcher(composer, NewPluginRunner(nil, nil), nil, nil, nil).
			WithInventoryTool(inventory).
			WithPrograms(jsrun.New(jsrun.Limits{}, 4)),
		rc: routable(consumer, regs...),
	}
}

func (w evalWorld) ctx(mode string) context.Context {
	ctx := identity.WithPrincipal(context.Background(), &identity.Principal{Subject: "me", Method: identity.MethodOAuth})
	return appgateway.WithGateway(ctx, &gatewaydomain.Gateway{ID: w.rc.Consumer.GatewayID, Metadata: gatewaydomain.WithMCPCodeMode(nil, mode)})
}

// dispatch makes one tools/call, as an MCP client would, and renders what
// came back as the tool result's text.
func (w evalWorld) dispatch(ctx context.Context, name string, input json.RawMessage) (string, bool) {
	params, _ := json.Marshal(map[string]any{"name": name, "arguments": input})
	result, err := w.d.Dispatch(ctx, w.rc, "", "tools/call", params)
	if err != nil {
		return err.Error(), true
	}
	raw, _ := json.Marshal(result)
	var envelope struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return string(raw), false
	}
	var texts []string
	for _, block := range envelope.Content {
		texts = append(texts, block.Text)
	}
	return strings.Join(texts, "\n"), envelope.IsError
}

func graded(answer string, want []string) bool {
	lower := strings.ToLower(answer)
	for _, w := range want {
		if !strings.Contains(lower, strings.ToLower(w)) {
			return false
		}
	}
	return true
}

// referencePrograms solve each task the way a model should, through
// trustgate_query: they check, without a model, that the fake servers and the
// graded answers agree.
var referencePrograms = map[string]string{
	"uncommented-issues": `const { issues } = await tools.linear_list_issues({ state: "started", assignee: "me" });
		const counts = await Promise.all(issues.map(i => tools.linear_list_comments({ issueId: i.id })));
		const none = issues.filter((i, k) => counts[k].comments.length === 0).map(i => i.id);
		return none.length + " " + none.join(", ");`,
	"most-commented": `const { issues } = await tools.linear_list_issues({ state: "started", assignee: "me" });
		const counts = await Promise.all(issues.map(i => tools.linear_list_comments({ issueId: i.id })));
		let best = 0; issues.forEach((i, k) => { if (counts[k].comments.length > counts[best].comments.length) best = k; });
		return issues[best].id;`,
	"last-commenter": `const { issues } = await tools.linear_list_issues({ state: "started", assignee: "me" });
		const counts = await Promise.all(issues.map(i => tools.linear_list_comments({ issueId: i.id })));
		return issues.map((i, k) => counts[k].comments.length ? i.id + ": " + counts[k].comments.at(-1).author : null).filter(Boolean).join("; ");`,
	"urgent-points": `const { issues } = await tools.linear_list_issues({ priority: "urgent" });
		return issues.reduce((sum, i) => sum + i.estimate, 0);`,
	"stale-payments-prs": `const { pull_requests } = await tools.github_list_pull_requests({ state: "open" });
		const details = await Promise.all(pull_requests.map(p => tools.github_get_pull_request({ number: p.number })));
		return details.filter(d => d.files.some(f => f.includes("payments")) && d.created_at < "2026-11-18").map(d => "#" + d.number).join(", ");`,
	"pr-reviewers": `const { pull_requests } = await tools.github_list_pull_requests({ state: "open" });
		const details = await Promise.all(pull_requests.map(p => tools.github_get_pull_request({ number: p.number })));
		const count = {}; details.forEach(d => d.reviewers.forEach(r => count[r] = (count[r] || 0) + 1));
		return Object.entries(count).sort((a, b) => b[1] - a[1])[0][0];`,
	"overlapping-meetings": `const { events } = await tools.calendar_list_events({ day: "2026-11-26" });
		const out = [];
		for (const a of events) for (const b of events) if (a !== b && a.start < b.end && b.start < a.end) out.push(a.title);
		return [...new Set(out)].join(", ");`,
	"issue-title": `return (await tools.linear_get_issue({ id: "ENG-102" })).title;`,
	"one-pr":      `return (await tools.github_get_pull_request({ number: 57 })).author;`,
	"cross-server": `const { pull_requests } = await tools.github_list_pull_requests({ state: "open" });
		const out = [];
		for (const p of pull_requests) {
			const m = p.title.match(/ENG-\d+/);
			if (!m) continue;
			const issue = await tools.linear_get_issue({ id: m[0] });
			out.push("#" + p.number + " " + m[0] + " " + issue.state);
		}
		return out.join("; ");`,
}

func TestCodeModeEval_ReferenceProgramsAnswerEveryTask(t *testing.T) {
	t.Parallel()
	w := newEvalWorld(t)
	ctx := w.ctx(gatewaydomain.MCPCodeModeReadOnly)
	for _, task := range evalTasks {
		code, ok := referencePrograms[task.Name]
		if !ok {
			t.Fatalf("%s has no reference program", task.Name)
		}
		input, _ := json.Marshal(map[string]string{"code": code})
		out, isError := w.dispatch(ctx, QueryToolName, input)
		if isError {
			t.Fatalf("%s: reference program failed: %s", task.Name, out)
		}
		if !graded(out, task.Want) {
			t.Fatalf("%s: reference answer %q lacks %q", task.Name, out, task.Want)
		}
	}
}
