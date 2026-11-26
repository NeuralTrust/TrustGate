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
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/jsrun"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

// A program that fails still hands back its message and its logs. They pass
// the response policies an answer passes, or throwing would get out what a
// policy kept the program from returning.
func TestCodeMode_AFailedProgramPassesTheResponsePolicies(t *testing.T) {
	t.Parallel()
	for name, code := range map[string]string{
		"thrown":  `await tools.LIST({}); throw new Error("SEC" + "RET");`,
		"logged":  `await tools.LIST({}); console.log("SEC" + "RET"); throw new Error("no");`,
		"stopped": `console.log("SEC" + "RET"); await tools.LIST({}); for (;;) {}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newCodeWorld(t, guardExecutor{})
			w.d.WithPrograms(jsrun.New(jsrun.Limits{Compute: 200 * time.Millisecond}, 4))
			w.rc.Policies = []*policydomain.Policy{{Enabled: true, Mode: policydomain.ModeEnforce, Stages: []policydomain.Stage{policydomain.StagePreResponse}}}
			_, text, _ := w.program(t, gatewaydomain.MCPCodeModeOn, ExecuteToolName, strings.ReplaceAll(code, "LIST", w.n("list_issues")))
			if text != "[masked]" {
				t.Fatalf("failure = %q, want the masked one", text)
			}
		})
	}
}

// recordingPlugin records the policies that ran on a stage.
type recordingPlugin struct {
	benchPlugin
	mu  *sync.Mutex
	ran *[]string
}

func (p *recordingPlugin) Execute(context.Context, appplugins.ExecInput) (*appplugins.Result, error) {
	p.mu.Lock()
	*p.ran = append(*p.ran, p.name)
	p.mu.Unlock()
	return &appplugins.Result{StatusCode: 200}, nil
}

// A policy scoped to one server saw that call's result; the answer a program
// built from it is that server's data too, so it passes that policy as well,
// next to every other server's the program called, each once.
func TestCodeMode_TheAnswerPassesThePoliciesOfEveryServerItCalled(t *testing.T) {
	t.Parallel()
	var (
		mu  sync.Mutex
		ran []string
	)
	reg := appplugins.NewRegistry()
	for _, slug := range []string{"base", "only-x", "only-y", "only-z"} {
		if err := reg.Register(&recordingPlugin{benchPlugin: benchPlugin{name: slug}, mu: &mu, ran: &ran}); err != nil {
			t.Fatalf("register: %v", err)
		}
	}
	x, y, z := benchRegistry("x"), benchRegistry("y"), benchRegistry("z")
	unscoped := []*policydomain.Policy{benchPolicy("Base", "base", nil)}
	scoped := []*policydomain.Policy{
		benchPolicy("X", "only-x", &policydomain.MCPScope{RegistryIDs: []ids.RegistryID{x.ID}}),
		benchPolicy("Y", "only-y", &policydomain.MCPScope{RegistryIDs: []ids.RegistryID{y.ID}}),
		benchPolicy("Z", "only-z", &policydomain.MCPScope{RegistryIDs: []ids.RegistryID{z.ID}}),
	}
	rc := &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: ids.New[ids.GatewayKind](), Type: consumerdomain.TypeMCP},
		MCPPlans: appconsumer.BuildPolicyPlans(reg, unscoped, scoped, discardLogger()),
	}
	called := func(regs ...*registryTarget) []programCall {
		var calls []programCall
		for _, r := range regs {
			calls = append(calls, programCall{target: &ResolvedTool{Registry: r.reg, Tool: Tool{Name: r.tool}}})
		}
		calls = append(calls, programCall{Tool: "unknown_tool"})
		return calls
	}
	runAnswer := func(t *testing.T, plan *appplugins.StagePlan) []string {
		t.Helper()
		mu.Lock()
		ran = nil
		mu.Unlock()
		_, err := appplugins.NewExecutor(reg, nil).RunStage(context.Background(), appplugins.StageInput{
			Stage:    policydomain.StagePreResponse,
			Plan:     plan,
			Request:  &infracontext.RequestContext{},
			Response: &infracontext.ResponseContext{},
		})
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		out := append([]string(nil), ran...)
		sort.Strings(out)
		return out
	}

	plan := answerPlan(context.Background(), rc, called(
		&registryTarget{x, "list"}, &registryTarget{y, "read"}, &registryTarget{x, "get"},
	))
	if got := runAnswer(t, plan); strings.Join(got, ",") != "base,only-x,only-y" {
		t.Fatalf("policies on the answer = %v, want base, only-x and only-y once each", got)
	}
	if plan := answerPlan(context.Background(), rc, called()); plan != nil {
		t.Fatal("a program whose calls reached no tool keeps the consumer's base plan")
	}
	rc.MCPPlans = nil
	if plan := answerPlan(context.Background(), rc, called(&registryTarget{x, "list"})); plan != nil {
		t.Fatal("a consumer without scoped plans keeps its base plan")
	}
}

type registryTarget struct {
	reg  *registrydomain.Registry
	tool string
}

// A call that failed for a reason the gateway did not word for callers is told
// to the program as the handler tells a client: the fact, not the error, which
// can carry an upstream URL with a token in it.
func TestCodeMode_AFailedCallIsToldInWordsSafeForTheCaller(t *testing.T) {
	t.Parallel()
	leak := errors.New(`Post "https://linear.example.com/mcp?token=SECRET-TOKEN": dial tcp 10.0.0.7:443: connection refused`)
	for _, tc := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("%w: registry %q: %w", ErrUpstreamUnavailable, "linear", leak), "upstream MCP server unreachable"},
		{fmt.Errorf("%w: %w", ErrUnreachable, leak), "upstream MCP server unreachable"},
		{fmt.Errorf("pool: %w", leak), "internal error"},
		{&ServerNotServingError{Server: "Linear", State: InventoryStateUnavailable}, (&ServerNotServingError{Server: "Linear", State: InventoryStateUnavailable}).Error()},
		{&ToolNotPermittedError{Tool: "linear_delete"}, (&ToolNotPermittedError{Tool: "linear_delete"}).Error()},
	} {
		if got := callerSafeText("linear_list_issues", tc.err); got != tc.want {
			t.Errorf("callerSafeText(%v) = %q, want %q", tc.err, got, tc.want)
		}
		res, _ := invokeFailure(tc.err, "linear_list_issues")
		resolved, _ := resolveFailure(tc.err, "linear_list_issues", nil)
		for _, r := range []jsrun.CallResult{res, resolved} {
			if r.Err == nil || strings.Contains(r.Err.Message, "SECRET-TOKEN") || strings.Contains(r.Err.Message, "10.0.0.7") {
				t.Errorf("the program was told %+v", r.Err)
			}
		}
	}

	w := newCodeWorld(t, nil)
	w.up.failures = map[string]error{"list_issues": leak}
	structured, text, _ := w.program(t, gatewaydomain.MCPCodeModeOn, ExecuteToolName, `
		try { await tools.`+w.n("list_issues")+`({}); return "called"; } catch (e) { return e.message; }
	`)
	raw, _ := json.Marshal(structured)
	if strings.Contains(text, "SECRET-TOKEN") || strings.Contains(string(raw), "SECRET-TOKEN") || strings.Contains(text, "10.0.0.7") {
		t.Fatalf("the program's answer carries the upstream's error: %s", text)
	}
}

// A program that reaches for one of the gateway's own tools is refused, and
// the refusal is in Activity like any refused call.
func TestCodeMode_ARefusedGatewayToolIsRecorded(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t, nil)
	outer := w.rt.StartSpan(trace.SpanMCP, "tools/call")
	ctx := trace.NewSpanContext(w.ctx(gatewaydomain.MCPCodeModeOn), outer)
	args, _ := json.Marshal(map[string]string{"code": `try { await tools.trustgate_search({}); } catch (e) { return e.name; }`})
	params, _ := json.Marshal(map[string]any{"name": ExecuteToolName, "arguments": json.RawMessage(args)})
	if _, err := w.d.Dispatch(ctx, w.rc, "", "tools/call", params); err != nil {
		t.Fatalf("program: %v", err)
	}
	for _, span := range w.rt.Spans() {
		attrs, ok := span.MCPAttrsCopy()
		if ok && attrs.Tool == SearchToolName && attrs.Program == ExecuteToolName {
			if attrs.UpstreamStatus != http.StatusForbidden {
				t.Fatalf("refused call recorded with status %d", attrs.UpstreamStatus)
			}
			return
		}
	}
	t.Fatal("the refused call to trustgate_search left no span")
}

// One gateway's programs share its own slots, so it cannot take every slot of
// the process.
func TestCodeMode_AGatewaysProgramsShareItsOwnSlots(t *testing.T) {
	t.Parallel()
	w := newCodeWorld(t, nil)
	w.d.WithPrograms(jsrun.New(jsrun.Limits{MaxPerTenant: 1, MaxWait: 100 * time.Millisecond}, 4))
	w.up.gated, w.up.gate, w.up.entered = "list_issues", make(chan struct{}), make(chan struct{}, 1)
	first := make(chan struct{})
	go func() {
		defer close(first)
		w.program(t, gatewaydomain.MCPCodeModeOn, ExecuteToolName, `return await tools.`+w.n("list_issues")+`({});`)
	}()
	<-w.up.entered
	structured, text, isError := w.program(t, gatewaydomain.MCPCodeModeOn, ExecuteToolName, `return 1;`)
	close(w.up.gate)
	<-first
	if !isError || structured["error"] != string(jsrun.KindBusy) || !strings.Contains(text, "already running 1") {
		t.Fatalf("second program = %q (%v)", text, structured)
	}
}
