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
	"strings"
	"sync"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
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
// trustgate_query runs programs that only read: they may call a tool its
// server annotates readOnlyHint, or one the server's admin lists in
// read_only_tools, and not one that declares it reaches an open world (a web
// search or a fetch could carry what the program read elsewhere) unless the
// admin listed it. trustgate_execute runs programs that may call any tool the
// user can call; clients ask the user before running it. A gateway offers
// neither, the first, or both (gateway mcp_code_mode).
//
// See docs/mcp/code-mode.md.

const (
	// QueryToolName runs a program that calls the user's read-only tools.
	QueryToolName = "trustgate_query"
	// ExecuteToolName runs a program that may call any of the user's tools.
	ExecuteToolName = "trustgate_execute"
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
	switch tool {
	case QueryToolName:
		return mode == gatewaydomain.MCPCodeModeReadOnly || mode == gatewaydomain.MCPCodeModeFull
	case ExecuteToolName:
		return mode == gatewaydomain.MCPCodeModeFull
	}
	return false
}

// CodeModeOffered reports which Code Mode tools the request's gateway offers.
func CodeModeOffered(ctx context.Context) (query, execute bool) {
	mode := codeModeOf(ctx)
	return codeModeOffers(mode, QueryToolName), codeModeOffers(mode, ExecuteToolName)
}

// CodeModeInstructions is the sentence the initialize instructions close with
// on a gateway with Code Mode on: when to write a program instead of calling
// tools one at a time. The tools' own descriptions say the same, for a client
// that does not pass instructions on.
func CodeModeInstructions(ctx context.Context, rc *appconsumer.RoutableConsumer) string {
	if !metaToolsPermitted(rc) {
		return ""
	}
	query, execute := CodeModeOffered(ctx)
	switch {
	case execute:
		return " For a task that takes several tool calls (a loop over results, filtering, joining or counting), find the tools with " + SearchToolName + " and do the work in one program: " + QueryToolName + " for one that only reads, " + ExecuteToolName + " for one that also writes. Only what the program returns comes back to you."
	case query:
		return " For a task that only reads and takes several tool calls (a loop over results, filtering, joining or counting), find the tools with " + SearchToolName + " and do the work in one " + QueryToolName + " program: only what it returns comes back to you."
	}
	return ""
}

// codeModeDefinitions are the Code Mode tools the gateway offers this
// request, none when Code Mode is off.
func (d *RPCDispatcher) codeModeDefinitions(ctx context.Context) []Tool {
	if d.inventoryImpl == nil || d.inventory == nil {
		return nil
	}
	mode := codeModeOf(ctx)
	limits := d.programs.Limits()
	var defs []Tool
	if codeModeOffers(mode, QueryToolName) {
		if def, err := programDefinition(QueryToolName, limits); err == nil {
			defs = append(defs, def)
		}
	}
	if codeModeOffers(mode, ExecuteToolName) {
		if def, err := programDefinition(ExecuteToolName, limits); err == nil {
			defs = append(defs, def)
		}
	}
	return defs
}

func programDefinition(name string, limits jsrun.Limits) (Tool, error) {
	var description, title string
	annotations := map[string]any{"idempotentHint": false, "openWorldHint": true}
	if name == QueryToolName {
		title = "Run a program that reads the user's tools"
		description = "Run a short JavaScript program on the gateway that calls the user's read-only tools and returns one result. " +
			"Use it instead of several " + GatewayCallToolName + " calls when a task needs more than one call, a loop over results, or filtering, joining or counting before you answer: only what the program returns comes back to you. "
		annotations["readOnlyHint"] = true
		annotations["destructiveHint"] = false
	} else {
		title = "Run a program that uses the user's tools"
		description = "Run a short JavaScript program on the gateway that calls any of the user's tools, including ones that create, change or delete, and returns one result. " +
			"Use it for a task of several steps that writes, such as updating every item a search finds. For a task that only reads, use " + QueryToolName + ". "
		annotations["readOnlyHint"] = false
		annotations["destructiveHint"] = true
	}
	description += "In the program, call a tool as `await tools.<name>(args)` with its exact name and the arguments its signature in " + SearchToolName + " gives (search first if you do not have them); calls run in parallel with Promise.all. " +
		"A call returns the tool's structured result, or its JSON text parsed, or its text; a failed call throws a ToolError you can catch. " +
		"`return` the smallest value that answers the task. console.log lines come back too. " +
		"There is no network, file or timer access, and no import of modules. " +
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
	Tool  string `json:"tool"`
	OK    bool   `json:"ok"`
	Ms    int64  `json:"ms"`
	Error string `json:"error,omitempty"`
}

// runProgram serves QueryToolName and ExecuteToolName.
func (d *RPCDispatcher) runProgram(ctx context.Context, req dispatchRequest, tool string, arguments json.RawMessage) (any, error) {
	// The program's own request is the gateway's; each tool it calls is
	// counted as that tool's call (see usage and the event builder).
	markMetaTool(ctx)
	if d.inventoryImpl == nil || d.inventory == nil || !metaToolsPermitted(req.consumer) {
		return nil, &ToolNotPermittedError{Tool: tool}
	}
	mode := codeModeOf(ctx)
	if !codeModeOffers(mode, tool) {
		d.programStats.ran(ctx, req.consumer, tool, programResultNotOffered, 0)
		text := tool + " is not turned on for this gateway."
		if tool == ExecuteToolName && codeModeOffers(mode, QueryToolName) {
			text = tool + " is not turned on for this gateway; " + QueryToolName + " is, for programs that only read."
		}
		return toolErrorResult(text+" Call the tools one at a time with "+GatewayCallToolName+".", map[string]any{"error": "not_enabled", "code_mode": mode})
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
	result, err := d.programs.Run(ctx, args.Code, func(ctx context.Context, call jsrun.Call) (jsrun.CallResult, error) {
		return d.programCall(ctx, req, tool, call, record)
	})
	elapsed := time.Since(started)
	var failed *jsrun.Error
	switch {
	case errors.As(err, &failed):
		d.programStats.ran(ctx, req.consumer, tool, string(failed.Kind), len(calls))
		d.programStats.took(ctx, req.consumer, tool, elapsed)
		return toolErrorResult(programFailureText(tool, failed, calls), map[string]any{
			"error":   failed.Kind,
			"message": failed.Message,
			"calls":   callsOrEmpty(calls),
			"logs":    logsOrEmpty(failed.Logs),
		})
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
	raw, err := marshalToolResult(text, structured)
	if err != nil {
		return nil, err
	}
	// What reaches the model is what the program made of its calls' results,
	// which each passed the response policies on their own; the program may
	// have decoded, joined or reshaped them, so its answer passes them too.
	post, err := d.plugins.PreResponse(ctx, req.consumer, ToolCall{Exposed: tool, Arguments: arguments}, raw)
	if err != nil {
		return nil, err
	}
	if post != nil && post.Result != nil {
		return post.Result, nil
	}
	return raw, nil
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
	done := func(res jsrun.CallResult, err error) (jsrun.CallResult, error) {
		c := programCall{Tool: call.Name, OK: err == nil && res.Err == nil, Ms: time.Since(started).Milliseconds()}
		if res.Err != nil {
			c.Error = res.Err.Name
		}
		record(c)
		return res, err
	}
	if isGatewayToolName(call.Name) || IsCodeModeToolName(call.Name) {
		return done(callError("NotAllowedError", call.Name+" is one of the gateway's own tools; a program calls the user's tools only."), nil)
	}
	// Each call is its own span: Activity and usage see the tools the program
	// called, each with its server, policies and outcome.
	span := startProgramSpan(ctx, program, call.Name)
	if span != nil {
		ctx = trace.NewSpanContext(ctx, span)
	}
	res, err := d.programCallTraced(ctx, req, program, call)
	finishProgramSpan(span, res, err)
	return done(res, err)
}

func (d *RPCDispatcher) programCallTraced(ctx context.Context, req dispatchRequest, program string, call jsrun.Call) (jsrun.CallResult, error) {
	if err := d.checkRateLimit(ctx, req.consumer); err != nil {
		return jsrun.CallResult{}, err
	}
	target, err := d.composer.Resolve(ctx, req.consumer, call.Name)
	if err != nil {
		d.searchStats.called(ctx, req.consumer, program, call.Name, toolInvocation{}, err)
		return resolveFailure(err, call.Name, d.closestToolNames(ctx, req.consumer, call.Name))
	}
	if program == QueryToolName {
		if refusal := readOnlyRefusal(target, call.Name, codeModeOf(ctx)); refusal != nil {
			if span := trace.SpanFromContext(ctx); span != nil {
				annotateRegistry(span, target.Registry, target.Tool.Name)
				span.SetMCPToolRisk(target.Tool.Risk())
			}
			return jsrun.CallResult{Err: refusal}, nil
		}
	}
	d.searchStats.called(ctx, req.consumer, program, call.Name, toolInvocation{target: target}, nil)
	result, _, err := d.invokeResolved(ctx, req, target, call.Arguments, nil)
	if err != nil {
		return invokeFailure(err)
	}
	return programValue(result), nil
}

// readOnlyRefusal is why a read-only program may not call the tool, nil when
// it may.
func readOnlyRefusal(target *ResolvedTool, name, mode string) *jsrun.CallError {
	listed := target.Registry != nil && target.Registry.MCPTarget.IsReadOnlyTool(target.Tool.Name)
	if listed {
		return nil
	}
	risk, _ := target.Tool.Risk()
	elsewhere := " Call it on its own with " + GatewayCallToolName
	if mode == gatewaydomain.MCPCodeModeFull {
		elsewhere += ", or from " + ExecuteToolName
	}
	elsewhere += "."
	switch {
	case risk != ToolRiskReadOnly:
		why := "may change something"
		if risk == "" {
			why = "does not say it only reads (its server does not annotate it)"
		}
		return &jsrun.CallError{Name: "NotAllowedError", Message: name + " " + why + ", so " + QueryToolName + " cannot call it." + elsewhere}
	case target.Tool.DeclaresOpenWorld():
		return &jsrun.CallError{Name: "NotAllowedError", Message: name + " reaches outside the user's own data (its server marks it open-world), so a read-only program cannot call it: what the program read could leave in its arguments." + elsewhere}
	}
	return nil
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
	return callError("ToolError", name+" could not be reached: "+err.Error()), nil
}

// invokeFailure is what the program sees when a call failed. A policy that
// refused the call is an error the program can catch, as is an upstream that
// failed; a consent or a rate limit ends the program.
func invokeFailure(err error) (jsrun.CallResult, error) {
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
		return callError("NotAllowedError", err.Error()), nil
	}
	return callError("ToolError", err.Error()), nil
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
