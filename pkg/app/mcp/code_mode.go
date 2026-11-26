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
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/app/identity/sts"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/jsrun"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

// Code Mode: the model writes a short JavaScript program that calls the
// user's tools, and the gateway runs it in a sandbox (pkg/infra/jsrun) and
// hands back what it returns. A task that takes several calls — list, then
// read each, then count — is one call for the model, and only the answer goes
// through its context, not every intermediate result.
//
// Every call a program makes is a tool call like any other: resolved through
// the consumer's toolkit, under the same consent, request and response
// policies, rate limit and audit as a direct call. A program can do nothing a
// direct call could not.
//
// One tool runs programs, trustgate_execute, offered when the gateway's Code
// Mode is on (gateway mcp_code_mode). A program may call any tool the user
// can call; what keeps a user's agent from writing is what keeps a direct
// call from it: the application's tool restrictions and the gateway's
// policies. The tool is marked destructive, so clients that confirm such tools
// show the person the program first. A client's own rules for single tools
// (allow this one, ask for that one) do not reach the calls inside a program:
// only the gateway sees those.
//
// What a program hands back, its answer or why it failed, passes the response
// policies of every server it called; a failed call is described to it in the
// words the tools/call handler would use with a client.
//
// See docs/mcp/code-mode.md.

const (
	// ExecuteToolName runs a program that may call any of the user's tools.
	ExecuteToolName = "trustgate_execute"
	// QueryToolName is retired. It ran programs that could call only tools
	// their servers marked read-only; a client that kept it in its tool list
	// is told to send the program to ExecuteToolName instead. It is not run:
	// that client listed it as read-only and may run it without asking.
	QueryToolName = "trustgate_query"
)

// IsCodeModeToolName reports whether name is one of the Code Mode tools.
func IsCodeModeToolName(name string) bool {
	return name == QueryToolName || name == ExecuteToolName
}

// codeModeOf is the Code Mode of the gateway serving the request, off when
// the request carries none.
func codeModeOf(ctx context.Context) string {
	gw, ok := appgateway.FromContext(ctx)
	if !ok {
		return gatewaydomain.MCPCodeModeOff
	}
	return gw.MCPCodeMode()
}

// codeModeOffers reports whether the gateway's Code Mode offers the tool.
func codeModeOffers(mode, tool string) bool {
	return tool == ExecuteToolName && mode == gatewaydomain.MCPCodeModeOn
}

// gatewayToolsOnly reports whether the request's gateway lists only its own
// tools.
func gatewayToolsOnly(ctx context.Context) bool {
	gw, ok := appgateway.FromContext(ctx)
	return ok && gw.MCPToolListing() == gatewaydomain.MCPToolListingGateway
}

// ToolListingInstructions tells a client of a gateway that lists only its own
// tools where the user's are.
func ToolListingInstructions(ctx context.Context, rc *appconsumer.RoutableConsumer) string {
	if !gatewayToolsOnly(ctx) || !metaToolsPermitted(rc) {
		return ""
	}
	return " The user's tools are not in your tool list: find them with " + SearchToolName + ` {"query": …} and call one with ` + GatewayCallToolName + ` {"tool": <name>, "arguments": {…}}.`
}

// CodeModeOffered reports whether the request's gateway offers
// ExecuteToolName.
func CodeModeOffered(ctx context.Context) bool {
	return codeModeOffers(codeModeOf(ctx), ExecuteToolName)
}

// CodeModeInstructions is the sentence the initialize instructions close with
// on a gateway with Code Mode on: when to write a program instead of calling
// tools one at a time. The tool's own description says the same, for a client
// that does not pass instructions on.
func CodeModeInstructions(ctx context.Context, rc *appconsumer.RoutableConsumer) string {
	if !metaToolsPermitted(rc) || !CodeModeOffered(ctx) {
		return ""
	}
	return " For a task that takes several tool calls (a loop over results, filtering, joining or counting), find the tools with " + SearchToolName + " and do the work in one " + ExecuteToolName + " program: only what it returns comes back to you." + programFallback
}

// programFallback tells a client whose tool list predates Code Mode how to
// run a program anyway.
const programFallback = " If " + ExecuteToolName + " is not in your tool list, call it through " + GatewayCallToolName + ` {"tool": "` + ExecuteToolName + `", "arguments": {"code": …}} or ` + CallToolName + ` {"name": "` + ExecuteToolName + `", "arguments": {"code": …}}.`

// ProgramHintForEarlierTools closes the earlier inventory tool's answer when
// the gateway runs Code Mode programs. A client that still uses the earlier
// tools fetched its list before Code Mode: this answer is the one place it
// learns that programs exist and how to run one.
func ProgramHintForEarlierTools(ctx context.Context) string {
	if !CodeModeOffered(ctx) {
		return ""
	}
	return "\n\nFor a task that takes several calls (a loop over results, filtering, joining or counting), run them in one program on the gateway: " +
		CallToolName + ` {"name": "` + ExecuteToolName + `", "arguments": {"code": <the body of an async JavaScript function>}}` +
		", calling each tool in it as await tools.<name>({…}) and returning the smallest answer."
}

// codeModeDefinitions are the Code Mode tools the gateway offers this
// request: ExecuteToolName when Code Mode is on, none when it is off.
func (d *RPCDispatcher) codeModeDefinitions(ctx context.Context) []Tool {
	if d.inventoryImpl == nil || d.inventory == nil || !CodeModeOffered(ctx) {
		return nil
	}
	def, err := programDefinition(d.programs.Limits())
	if err != nil {
		return nil
	}
	return []Tool{def}
}

// programDefinition is ExecuteToolName as clients list it. It is marked
// destructive: a program may call tools that write, and clients that confirm
// such tools show the person the program before it runs.
func programDefinition(limits jsrun.Limits) (Tool, error) {
	name := ExecuteToolName
	annotations := map[string]any{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": true}
	title := "Run a program that uses the user's tools"
	description := "Run a short JavaScript program on the gateway that calls the user's tools and returns one result. " +
		"Use it instead of several " + GatewayCallToolName + " calls when a task needs more than one call, a loop over results, or filtering, joining or counting before you answer: only what the program returns comes back to you. " +
		"In the program, call a tool as `await tools.<name>(args)` with its exact name and the arguments its signature in " + SearchToolName + " gives (search first if you do not have them); calls run in parallel with Promise.all. " +
		"A call returns the tool's structured result, or its JSON text parsed, or its text; a failed call throws a ToolError you can catch. " +
		"`return` the smallest value that answers the task. console.log lines come back too. " +
		"There is no network, file or timer access, and no import of modules. " +
		"If it stops early (its time, a consent or a rate limit), the calls it already made stay made. " +
		fmt.Sprintf("Limits: %s, %d tool calls, %d KB of result.", limits.Timeout, limits.MaxCalls, limits.MaxOutputBytes/1000) +
		consolidatedToolDisclaimer
	return toolFromDefinition(map[string]any{
		"name":        name,
		"title":       title,
		"description": description,
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"code": map[string]any{
					"type":        "string",
					"description": "The body of an async JavaScript function, for example: const { issues } = await tools.linear_list_issues({ state: \"started\" }); return issues.length;",
				},
			},
			"required":             []string{"code"},
			"additionalProperties": false,
		},
		"annotations": annotations,
	})
}

// programCall is one call a program made, as its answer reports it.
type programCall struct {
	Tool string `json:"tool"`
	// Server is the server the tool resolved to, empty when it resolved to none.
	Server string `json:"server,omitempty"`
	OK     bool   `json:"ok"`
	Ms     int64  `json:"ms"`
	Error  string `json:"error,omitempty"`
	// registry is where the call went, for attributing the program's request.
	registry *registrydomain.Registry
	// target is the tool the call resolved to, nil when it resolved to none;
	// its plan is one the program's answer passes.
	target *ResolvedTool
	// bytes is what the call handed the program: its result, or its error.
	bytes int64
}

// runProgram serves ExecuteToolName, and answers the retired QueryToolName.
func (d *RPCDispatcher) runProgram(ctx context.Context, req dispatchRequest, tool string, arguments json.RawMessage) (any, error) {
	// The program's own request is the gateway's; each tool it calls is
	// counted as that tool's call (see usage and the event builder).
	markMetaTool(ctx)
	if d.inventoryImpl == nil || d.inventory == nil || !metaToolsPermitted(req.consumer) {
		return nil, &ToolNotPermittedError{Tool: tool}
	}
	mode := codeModeOf(ctx)
	if tool == QueryToolName && codeModeOffers(mode, ExecuteToolName) {
		d.programStats.ran(ctx, req.consumer, tool, programResultNotOffered, 0)
		return toolErrorResult(QueryToolName+" was replaced by "+ExecuteToolName+". Send the same code to "+ExecuteToolName+".", map[string]any{"error": "replaced", "use": ExecuteToolName})
	}
	if !codeModeOffers(mode, tool) {
		d.programStats.ran(ctx, req.consumer, tool, programResultNotOffered, 0)
		return toolErrorResult("Code Mode is not turned on for this gateway. Call the tools one at a time with "+GatewayCallToolName+".", map[string]any{"error": "not_enabled", "code_mode": mode})
	}
	var args struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(arguments, &args); err != nil || strings.TrimSpace(args.Code) == "" {
		d.programStats.ran(ctx, req.consumer, tool, programResultInvalid, 0)
		return toolErrorResult(tool+` takes {"code": <the body of an async JavaScript function>}. Send the program as code.`, map[string]any{"error": "invalid_arguments"})
	}

	var (
		mu    sync.Mutex
		calls []programCall
	)
	record := func(c programCall) {
		mu.Lock()
		calls = append(calls, c)
		mu.Unlock()
	}
	started := time.Now()
	// A gateway's programs share its own slots on this process, so no tenant
	// can take every slot.
	runCtx := jsrun.WithTenant(ctx, req.consumer.Consumer.GatewayID.String())
	result, err := d.programs.Run(runCtx, args.Code, func(ctx context.Context, call jsrun.Call) (jsrun.CallResult, error) {
		return d.programCall(ctx, req, tool, call, record)
	})
	elapsed := time.Since(started)
	attributeProgram(ctx, calls)
	var failed *jsrun.Error
	switch {
	case errors.As(err, &failed):
		d.programStats.ran(ctx, req.consumer, tool, string(failed.Kind), len(calls))
		d.programStats.took(ctx, req.consumer, tool, elapsed)
		text := programFailureText(tool, failed, calls)
		d.recordProgramBytes(ctx, req, tool, calls, len(text))
		raw, err := toolErrorResult(text, map[string]any{
			"error":   failed.Kind,
			"message": failed.Message,
			"calls":   callsOrEmpty(calls),
			"logs":    logsOrEmpty(failed.Logs),
		})
		if err != nil {
			return nil, err
		}
		// A program that fails still hands back its message and its logs,
		// built from what its calls returned: they pass the same policies as
		// an answer, or a program could throw what a policy kept it from
		// returning.
		return d.programAnswer(ctx, req, tool, arguments, calls, raw)
	case err != nil:
		// A consent the user must give or a rate limit: the program stops and
		// the client gets what a direct call would have got.
		d.programStats.ran(ctx, req.consumer, tool, programResultAborted, len(calls))
		return nil, err
	}
	d.programStats.ran(ctx, req.consumer, tool, programResultOK, len(calls))
	d.programStats.took(ctx, req.consumer, tool, elapsed)

	structured := map[string]any{
		"result": result.Value,
		"calls":  callsOrEmpty(calls),
	}
	text := string(result.Value)
	if len(result.Logs) > 0 {
		structured["logs"] = result.Logs
		text += "\n\nLogs:\n" + strings.Join(result.Logs, "\n")
	}
	if result.LogsDropped > 0 {
		structured["logs_dropped"] = result.LogsDropped
		text += fmt.Sprintf("\n(%d more log lines dropped)", result.LogsDropped)
	}
	d.recordProgramBytes(ctx, req, tool, calls, len(text))
	raw, err := marshalToolResult(text, structured)
	if err != nil {
		return nil, err
	}
	return d.programAnswer(ctx, req, tool, arguments, calls, raw)
}

// programAnswer passes what a program hands back through the response
// policies. What reaches the model is what the program made of its calls'
// results, which each passed the response policies on their own; the program
// may have decoded, joined or reshaped them, so its answer passes them too,
// under the plan of every server it called (see answerPlan).
func (d *RPCDispatcher) programAnswer(
	ctx context.Context,
	req dispatchRequest,
	tool string,
	arguments json.RawMessage,
	calls []programCall,
	raw json.RawMessage,
) (any, error) {
	call := ToolCall{Exposed: tool, Arguments: arguments, Plan: answerPlan(ctx, req.consumer, calls)}
	post, err := d.plugins.PreResponse(ctx, req.consumer, call, raw)
	if err != nil {
		return nil, err
	}
	if post != nil && post.Result != nil {
		return post.Result, nil
	}
	return raw, nil
}

// answerPlan is the plan a program's answer passes: every policy that ran on
// one of its calls, each once. A policy scoped to one server (or one tool, or
// one group of users) saw that call's result; the answer the program built
// from it is that server's data too. Without scoped plans, or when no call
// reached a tool, it is nil: the consumer's base plan.
func answerPlan(ctx context.Context, rc *appconsumer.RoutableConsumer, calls []programCall) *appplugins.StagePlan {
	if rc == nil || rc.MCPPlans == nil {
		return nil
	}
	principal := identity.PrincipalFromContext(ctx)
	var plans []*appplugins.StagePlan
	seen := make(map[*appplugins.StagePlan]struct{})
	for _, c := range calls {
		if c.target == nil {
			continue
		}
		plan := rc.MCPPlans.PlanFor(c.target.Registry, c.target.Tool.Name, principal)
		if plan == nil {
			continue
		}
		if _, dup := seen[plan]; dup {
			continue
		}
		seen[plan] = struct{}{}
		plans = append(plans, plan)
	}
	if len(plans) == 0 {
		return nil
	}
	return plans[0].Union(plans[1:]...)
}

// programCall runs one call a program made, exactly as a direct call would
// run, and turns what came back into what the program sees.
func (d *RPCDispatcher) programCall(
	ctx context.Context,
	req dispatchRequest,
	program string,
	call jsrun.Call,
	record func(programCall),
) (jsrun.CallResult, error) {
	started := time.Now()
	var target *ResolvedTool
	done := func(res jsrun.CallResult, err error) (jsrun.CallResult, error) {
		c := programCall{Tool: call.Name, OK: err == nil && res.Err == nil, Ms: time.Since(started).Milliseconds(), target: target, bytes: int64(len(res.Value))}
		if target != nil {
			c.registry = target.Registry
			c.Server = target.Registry.Name
		}
		if res.Err != nil {
			c.Error = res.Err.Name
			c.bytes += int64(len(res.Err.Message) + len(res.Err.Data))
		}
		record(c)
		return res, err
	}
	// Each call is its own span: Activity and usage see the tools the program
	// called, each with its server, policies and outcome, a refused one too.
	span := startProgramSpan(ctx, program, call.Name)
	if span != nil {
		ctx = trace.NewSpanContext(ctx, span)
	}
	if isGatewayToolName(call.Name) || IsCodeModeToolName(call.Name) {
		res := callError("NotAllowedError", call.Name+" is one of the gateway's own tools; a program calls the user's tools only.")
		finishProgramSpan(span, res, nil)
		return done(res, nil)
	}
	res, err := d.programCallTraced(ctx, req, program, call, &target)
	finishProgramSpan(span, res, err)
	return done(res, err)
}

func (d *RPCDispatcher) programCallTraced(ctx context.Context, req dispatchRequest, program string, call jsrun.Call, resolved **ResolvedTool) (jsrun.CallResult, error) {
	if err := d.checkRateLimit(ctx, req.consumer); err != nil {
		return jsrun.CallResult{}, err
	}
	target, err := d.composer.Resolve(ctx, req.consumer, call.Name)
	if err != nil {
		d.searchStats.called(ctx, req.consumer, program, call.Name, toolInvocation{}, err)
		return resolveFailure(err, call.Name, d.closestToolNames(ctx, req.consumer, call.Name))
	}
	*resolved = target
	d.searchStats.called(ctx, req.consumer, program, call.Name, toolInvocation{target: target}, nil)
	result, _, err := d.invokeResolved(ctx, req, target, call.Arguments, nil)
	if err != nil {
		return invokeFailure(err, call.Name)
	}
	return programValue(result), nil
}

func callError(name, message string) jsrun.CallResult {
	return jsrun.CallResult{Err: &jsrun.CallError{Name: name, Message: message}}
}

// resolveFailure is what the program sees when a name does not resolve. A
// consent the user must give ends the program, as it ends a direct call.
func resolveFailure(err error, name string, closest []string) (jsrun.CallResult, error) {
	var consent *ConsentRequiredError
	if errors.As(err, &consent) {
		return jsrun.CallResult{}, err
	}
	var notPermitted *ToolNotPermittedError
	switch {
	case errors.Is(err, ErrToolNotFound):
		msg := name + " is not one of the user's tools."
		if len(closest) > 0 {
			msg += " The closest are: " + strings.Join(closest, ", ") + "."
		} else {
			msg += " Find the exact name with " + SearchToolName + "."
		}
		return callError("NotFoundError", msg), nil
	case errors.As(err, &notPermitted):
		return callError("NotAllowedError", name+" is not one of the tools this connection may call."), nil
	}
	return callError("ToolError", name+" could not be reached: "+callerSafeText(name, err)), nil
}

// callerSafeText is what a program is told of a call that failed with err, on
// the terms the tools/call handler answers a client with (writeAppError in
// pkg/api/handler/http/mcp). An error the gateway wrote for callers is said as
// it is. One it did not classify can carry whatever the layer that raised it
// put there (an upstream URL with a token in its query, a driver message): the
// program, and the model it answers, get the fact, and the log gets the error.
func callerSafeText(tool string, err error) string {
	var (
		notConnected *ApplicationNotConnectedError
		notServing   *ServerNotServingError
		notPermitted *ToolNotPermittedError
	)
	switch {
	case errors.As(err, &notConnected):
		return notConnected.Error()
	case errors.As(err, &notServing):
		return notServing.Error()
	case errors.As(err, &notPermitted):
		return notPermitted.Error()
	case errors.Is(err, ErrToolNotFound), errors.Is(err, ErrNoPrincipal),
		errors.Is(err, ErrUpstreamNeedsCallerToken), errors.Is(err, ErrAudienceMismatch),
		errors.Is(err, sts.ErrNoUserIdentity), errors.Is(err, sts.ErrInteractionRequired),
		errors.Is(err, registrydomain.ErrURLTemplate):
		return err.Error()
	case errors.Is(err, sts.ErrIdentityIssuerMismatch):
		return sts.ErrIdentityIssuerMismatch.Error()
	case errors.Is(err, sts.ErrExchangeIdentityUnavailable):
		return sts.ErrExchangeIdentityUnavailable.Error()
	case errors.Is(err, ErrUnreachable), errors.Is(err, ErrUpstreamUnavailable):
		slog.Default().Warn("mcp code mode: a program's call found its upstream unreachable", "tool", tool, "error", err)
		return "upstream MCP server unreachable"
	}
	slog.Default().Error("mcp code mode: unclassified error on a program's call", "tool", tool, "error", err)
	return "internal error"
}

// invokeFailure is what the program sees when a call to tool failed. A policy
// that refused the call is an error the program can catch, as is an upstream
// that failed; a consent or a rate limit ends the program.
func invokeFailure(err error, tool string) (jsrun.CallResult, error) {
	var consent *ConsentRequiredError
	if errors.As(err, &consent) {
		return jsrun.CallResult{}, err
	}
	var rpcErr *RPCError
	if errors.As(err, &rpcErr) {
		switch rpcErr.Code {
		case CodeRateLimited, CodeConsentRequired:
			return jsrun.CallResult{}, err
		case CodePolicyBlocked:
			return callError("PolicyError", "a policy refused the call: "+rpcErr.Message), nil
		}
		return jsrun.CallResult{Err: &jsrun.CallError{Name: "ToolError", Message: rpcErr.Message, Data: rpcErr.Data}}, nil
	}
	var notPermitted *ToolNotPermittedError
	if errors.As(err, &notPermitted) {
		return callError("NotAllowedError", notPermitted.Error()), nil
	}
	return callError("ToolError", callerSafeText(tool, err)), nil
}

// programValue turns a tool's result into what the program sees: its
// structured content; else its one text block, parsed when it is JSON; else
// its blocks, the text ones as text. A result marked isError is thrown.
func programValue(result any) jsrun.CallResult {
	raw, ok := result.(json.RawMessage)
	if !ok {
		encoded, err := json.Marshal(result)
		if err != nil {
			return callError("ToolError", "the tool's result could not be read")
		}
		raw = encoded
	}
	var r struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StructuredContent json.RawMessage `json:"structuredContent"`
		IsError           bool            `json:"isError"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return jsrun.CallResult{Value: raw}
	}
	if r.IsError {
		var texts []string
		for _, block := range r.Content {
			if block.Type == "text" && block.Text != "" {
				texts = append(texts, block.Text)
			}
		}
		msg := strings.Join(texts, "\n")
		if msg == "" {
			msg = "the tool returned an error"
		}
		return jsrun.CallResult{Err: &jsrun.CallError{Name: "ToolError", Message: truncateRunes(msg, 2000), Data: r.StructuredContent}}
	}
	if s := strings.TrimSpace(string(r.StructuredContent)); s != "" && s != "null" {
		return jsrun.CallResult{Value: r.StructuredContent}
	}
	if len(r.Content) == 1 && r.Content[0].Type == "text" {
		text := strings.TrimSpace(r.Content[0].Text)
		if (strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[")) && json.Valid([]byte(text)) {
			return jsrun.CallResult{Value: json.RawMessage(text)}
		}
		encoded, _ := json.Marshal(r.Content[0].Text)
		return jsrun.CallResult{Value: encoded}
	}
	blocks := make([]any, 0, len(r.Content))
	for _, block := range r.Content {
		if block.Type == "text" {
			blocks = append(blocks, block.Text)
			continue
		}
		blocks = append(blocks, map[string]any{"type": block.Type, "omitted": true})
	}
	encoded, _ := json.Marshal(blocks)
	return jsrun.CallResult{Value: encoded}
}

// closestToolNames are the user's tools whose names come closest to name.
func (d *RPCDispatcher) closestToolNames(ctx context.Context, rc *appconsumer.RoutableConsumer, name string) []string {
	if d.inventoryImpl == nil {
		return nil
	}
	inventory, err := d.inventoryImpl.surface.ToolInventory(ctx, rc)
	if err != nil {
		return nil
	}
	candidates := d.candidates(inventory, "")
	docs := make([]searchDoc, len(candidates))
	for i, c := range candidates {
		docs[i] = searchDoc{Name: c.entry.Name, Title: c.entry.Title, Server: c.server.Name, Code: c.server.Code, Description: c.entry.Description}
	}
	var out []string
	for _, r := range rankSearchDocs(name, docs) {
		if len(out) == 3 {
			break
		}
		out = append(out, candidates[r.Index].entry.Name)
	}
	return out
}

// attributeProgram names, on the program's own span, the servers its calls
// went to: Activity's Provider for the program is them, not the gateway. One
// server is named as a direct call would name it; several by their names,
// with no registry, host or catalog code, since none of those is the
// program's.
// recordProgramBytes puts on the program's request, and on Code Mode's
// metrics, what its calls handed it and what it handed back to the client
// (returned): the model read the second instead of the first.
func (d *RPCDispatcher) recordProgramBytes(ctx context.Context, req dispatchRequest, tool string, calls []programCall, returned int) {
	var read int64
	for _, c := range calls {
		read += c.bytes
	}
	if span := trace.SpanFromContext(ctx); span != nil {
		span.SetMCPProgramBytes(read, int64(returned))
	}
	d.programStats.moved(ctx, req.consumer, tool, read, int64(returned))
}

func attributeProgram(ctx context.Context, calls []programCall) {
	span := trace.SpanFromContext(ctx)
	if span == nil {
		return
	}
	var servers []*registrydomain.Registry
	seen := make(map[string]struct{})
	for _, c := range calls {
		if c.registry == nil {
			continue
		}
		key := c.registry.ID.String()
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		servers = append(servers, c.registry)
	}
	switch len(servers) {
	case 0:
		return
	case 1:
		annotateRegistry(span, servers[0], "")
	default:
		names := make([]string, 0, len(servers))
		for _, reg := range servers {
			names = append(names, reg.Name)
		}
		span.SetMCPUpstream(strings.Join(names, ", "), "", "", "", "", "")
	}
}

func startProgramSpan(ctx context.Context, program, tool string) *trace.Span {
	rt := trace.FromContext(ctx)
	if rt == nil {
		return nil
	}
	span := rt.StartSpan(trace.SpanMCP, "tools/call")
	span.SetMCPRequest("tools/call", "tool", tool, "", "")
	span.SetMCPProgram(program)
	return span
}

// finishProgramSpan records how a program's call ended, on the terms the
// request's own span uses for a direct call.
func finishProgramSpan(span *trace.Span, res jsrun.CallResult, err error) {
	if span == nil {
		return
	}
	defer span.End()
	var rpcErr *RPCError
	var consent *ConsentRequiredError
	switch {
	case err == nil && res.Err == nil:
		span.SetMCPStatus(http.StatusOK, 0)
	case errors.As(err, &rpcErr):
		span.SetError(err.Error())
		span.SetMCPStatus(rpcErr.ResolvedHTTPStatus(), int(rpcErr.Code))
	case errors.As(err, &consent):
		span.SetError(err.Error())
		span.SetMCPStatus(http.StatusForbidden, int(CodeConsentRequired))
	case err != nil:
		span.SetError(err.Error())
		span.SetMCPStatus(http.StatusBadGateway, 0)
	default:
		span.SetError(res.Err.Name + ": " + res.Err.Message)
		switch res.Err.Name {
		case "NotFoundError":
			span.SetMCPStatus(http.StatusNotFound, 0)
		case "NotAllowedError":
			span.SetMCPStatus(http.StatusForbidden, int(CodePolicyBlocked))
		case "PolicyError":
			span.SetMCPStatus(http.StatusForbidden, int(CodePolicyBlocked))
		default:
			// The tool answered, with an error: the call reached it.
			span.SetMCPStatus(http.StatusOK, 0)
		}
	}
}

func programFailureText(tool string, failed *jsrun.Error, calls []programCall) string {
	var b strings.Builder
	b.WriteString(failed.Message)
	if len(calls) > 0 {
		fmt.Fprintf(&b, "\n\nCalls made before it stopped (%d):", len(calls))
		for i, c := range calls {
			if i == 10 {
				fmt.Fprintf(&b, "\n… and %d more", len(calls)-10)
				break
			}
			status := "ok"
			if !c.OK {
				status = c.Error
			}
			fmt.Fprintf(&b, "\n- %s: %s", c.Tool, status)
		}
	}
	if len(failed.Logs) > 0 {
		b.WriteString("\n\nLogs:\n" + strings.Join(failed.Logs, "\n"))
	}
	b.WriteString("\n\nFix the program and call " + tool + " again.")
	return b.String()
}

func callsOrEmpty(calls []programCall) []programCall {
	if calls == nil {
		return []programCall{}
	}
	return calls
}

func logsOrEmpty(logs []string) []string {
	if logs == nil {
		return []string{}
	}
	return logs
}
