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

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/infra/jsrun"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"go.opentelemetry.io/otel/metric"
)

var ErrMethodNotFound = errors.New("mcp: method not found")

// toolCallIDMetaKey is the params._meta key an agent uses to tell the gateway
// which LLM tool_call_id a tools/call is executing, so a policy watching both
// protocols counts the execution once (ENG-1579). The reverse-DNS prefix keeps
// it out of the way of the keys the MCP spec reserves.
const toolCallIDMetaKey = "ai.neuraltrust/toolCallId"

// agentToolCallIDMetaKeys are the params._meta keys under which agents already
// send the id of the tool call they are executing, read after toolCallIDMetaKey.
// It is the id the agent's hook reports as tool_use_id, so TrustGuard can count
// a call checked by both the hook and the gateway once.
var agentToolCallIDMetaKeys = []string{
	"claudecode/toolUseId", // Claude Code: the Anthropic tool_use id, "toolu_…"
	"callId",               // Codex: the model's call id, "call_…"
}

// maxToolCallIDLen bounds what a caller can put in a Redis key derived from the
// id. Real ids are short ("call_abc123", "toolu_01A…").
const maxToolCallIDLen = 128

type InvalidParamsError struct {
	Reason string
}

func (e *InvalidParamsError) Error() string { return "mcp: invalid params: " + e.Reason }

type dispatchRequest struct {
	consumer *appconsumer.RoutableConsumer
	baseURL  string
	params   json.RawMessage
}

type rpcHandler func(context.Context, dispatchRequest) (any, error)

type RPCDispatcher struct {
	composer    Composer
	plugins     *PluginRunner
	limiter     ratelimitapp.Checker
	connections ConnectionTool
	store       StoreTool
	inventory   InventoryTool
	// inventoryImpl is the inventory the consolidated tools read the surface
	// and the catalog through; nil when the inventory is not this package's.
	inventoryImpl *inventoryTool
	agents        AgentTools
	storeScoper   appstore.Scoper
	searchStats   *searchMetrics
	// programs runs Code Mode programs; programStats counts them.
	programs     *jsrun.Runner
	programStats *programMetrics
	handlers     map[string]rpcHandler
}

func NewRPCDispatcher(
	composer Composer,
	plugins *PluginRunner,
	limiter ratelimitapp.Checker,
	connections ConnectionTool,
	store StoreTool,
) *RPCDispatcher {
	if limiter == nil {
		limiter = ratelimitapp.NewNoopChecker()
	}
	d := &RPCDispatcher{
		composer: composer, plugins: plugins, limiter: limiter,
		connections: connections, store: store,
		searchStats:  newSearchMetrics(nil),
		programs:     jsrun.New(jsrun.Limits{}, 0),
		programStats: newProgramMetrics(nil),
	}
	d.handlers = map[string]rpcHandler{
		"tools/list":               d.listTools,
		"tools/call":               d.callTool,
		"resources/list":           d.listResources,
		"resources/templates/list": d.listResourceTemplates,
		"resources/read":           d.readResource,
		"prompts/list":             d.listPrompts,
		"prompts/get":              d.getPrompt,
	}
	return d
}

func (d *RPCDispatcher) WithInventoryTool(inventory InventoryTool) *RPCDispatcher {
	d.inventory = inventory
	d.inventoryImpl, _ = inventory.(*inventoryTool)
	return d
}

// WithAgentTools wires the Store's agent meta-tools (see AgentTools).
func (d *RPCDispatcher) WithAgentTools(agents AgentTools) *RPCDispatcher {
	d.agents = agents
	return d
}

// WithSearchMeter records trustgate_search's metrics on meter instead of the
// global meter provider's.
func (d *RPCDispatcher) WithSearchMeter(meter metric.Meter) *RPCDispatcher {
	d.searchStats = newSearchMetrics(meter)
	d.programStats = newProgramMetrics(meter)
	return d
}

// WithPrograms runs Code Mode programs with runner instead of one with the
// default limits.
func (d *RPCDispatcher) WithPrograms(runner *jsrun.Runner) *RPCDispatcher {
	if runner != nil {
		d.programs = runner
	}
	return d
}

func (d *RPCDispatcher) WithStoreScoper(scoper appstore.Scoper) *RPCDispatcher {
	d.storeScoper = scoper
	return d
}

func (d *RPCDispatcher) StoreScoper() appstore.Scoper {
	if d == nil {
		return nil
	}
	return d.storeScoper
}

func (d *RPCDispatcher) Dispatch(
	ctx context.Context,
	consumer *appconsumer.RoutableConsumer,
	baseURL,
	method string,
	params json.RawMessage,
) (any, error) {
	if d.storeScoper != nil {
		if scoped, err := d.storeScoper.Scope(ctx, consumer); err == nil {
			consumer = scoped
		}
	}
	handler, ok := d.handlers[method]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrMethodNotFound, method)
	}
	return handler(ctx, dispatchRequest{consumer: consumer, baseURL: baseURL, params: params})
}

// emptySurfaceInsteadOfError reports whether a listing should come back empty
// rather than as an error.
//
// A server waiting on an account is never a fault, whoever is asking: a pending
// consent waits on the person, and a server with no account for this caller
// waits on an administrator or on the end user the application names
// (ENG-1787). The listing leaves it out, the inventory meta-tool says why, and a
// call to one of its tools still answers the refusal.
//
// A person — or an end user an application named — may simply have connected
// nothing yet, and an empty list is the honest answer to "what can I use".
// Nothing attached at all is that same answer for the application itself: the
// surface is empty, and a client that lists tools while connecting must not
// fail the handshake. An unreachable upstream is still about who is asking.
// Registries were bound and could not be reached, so a request running as the
// application reports that fault; a person gets the empty list.
func emptySurfaceInsteadOfError(ctx context.Context, consumer *appconsumer.RoutableConsumer, err error) bool {
	if fixableByConnecting(err) {
		return true
	}
	if errors.Is(err, ErrNoMCPRegistries) {
		return true
	}
	return perUserCaller(ctx, consumer) && errors.Is(err, ErrUpstreamUnavailable)
}

// perUserCaller reports whether somebody other than the application itself is
// behind this request.
func perUserCaller(ctx context.Context, consumer *appconsumer.RoutableConsumer) bool {
	if consumer == nil || consumer.Consumer == nil {
		return false
	}
	if consumerdomain.IsStoreConsumer(consumer.Consumer) {
		return true
	}
	p := identity.PrincipalFromContext(ctx)
	return p != nil && p.Subject != "" && p.Subject != consumerdomain.AppSubject(consumer.Consumer.ID)
}

func (d *RPCDispatcher) listTools(ctx context.Context, req dispatchRequest) (any, error) {
	if err := d.checkRateLimit(ctx, req.consumer); err != nil {
		return nil, err
	}
	if gatewayToolsOnly(ctx) && d.inventoryImpl != nil && metaToolsPermitted(req.consumer) {
		// The gateway lists only its own tools: the user's are found with
		// trustgate_search and called with trustgate_call or from a program,
		// so the upstreams are not even asked for their lists here.
		tools := appendGatewayTools([]Tool{}, d.consolidatedDefinitions(ctx, req.consumer))
		tools = appendGatewayTools(tools, d.codeModeDefinitions(ctx))
		return map[string]any{"tools": tools}, nil
	}
	tools, err := d.composer.ListTools(ctx, req.consumer)
	if err != nil {
		if !emptySurfaceInsteadOfError(ctx, req.consumer, err) {
			return nil, err
		}
		tools = nil
	}
	if tools == nil {
		tools = []Tool{}
	}
	result := map[string]any{"tools": tools}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	if err := d.plugins.PreResponseDiscovery(ctx, req.consumer, raw); err != nil {
		return nil, err
	}
	// The gateway's own tools are the consolidated three. The earlier ones
	// (the inventory, the call-through, the connect tools, the Store's and the
	// agents') are no longer listed, but every one of them still answers
	// tools/call: a client that kept the list it fetched before — Claude's
	// hosted connectors keep theirs until the person reconnects — keeps
	// working.
	tools = appendGatewayTools(withoutGatewayNames(tools), d.consolidatedDefinitions(ctx, req.consumer))
	if metaToolsPermitted(req.consumer) {
		tools = appendGatewayTools(tools, d.codeModeDefinitions(ctx))
	}
	result["tools"] = tools
	return result, nil
}

// withoutGatewayNames drops an upstream tool named like one of the gateway's
// own. A call to that name reaches the gateway, never the upstream, so listing
// the upstream's definition would only put words it chose in front of the
// model under a name the gateway answers.
func withoutGatewayNames(tools []Tool) []Tool {
	out := tools[:0:0]
	for _, tool := range tools {
		if isGatewayToolName(tool.Name) {
			continue
		}
		out = append(out, tool)
	}
	return out
}

// consolidatedDefinitions are the gateway's own tools on the consolidated
// surface: the same three for every consumer, with the kinds and actions this
// consumer can use. A toolkit that names no tool gets none, as on the earlier
// surface.
func (d *RPCDispatcher) consolidatedDefinitions(ctx context.Context, rc *appconsumer.RoutableConsumer) []Tool {
	if !metaToolsPermitted(rc) {
		return nil
	}
	var defs []Tool
	store := isStore(rc)
	if d.inventoryImpl != nil {
		if def, err := searchDefinition(d.searchKinds(ctx, rc), store); err == nil {
			defs = append(defs, def)
		}
	}
	if d.inventory != nil {
		if def, err := gatewayCallDefinition(store && d.agents != nil); err == nil {
			defs = append(defs, def)
		}
	}
	if actions := d.accessActions(ctx, rc); len(actions) > 0 {
		if def, err := accessDefinition(actions, store); err == nil {
			defs = append(defs, def)
		}
	}
	return defs
}

func markMetaTool(ctx context.Context) {
	if rt := trace.FromContext(ctx); rt != nil {
		rt.MarkMetaTool()
	}
}

func (d *RPCDispatcher) callTool(ctx context.Context, req dispatchRequest) (any, error) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments,omitempty"`
		Meta      json.RawMessage `json:"_meta,omitempty"`
	}
	if err := json.Unmarshal(req.params, &params); err != nil || params.Name == "" {
		return nil, &InvalidParamsError{Reason: "tools/call requires params.name"}
	}
	if err := d.checkRateLimit(ctx, req.consumer); err != nil {
		return nil, err
	}
	switch params.Name {
	case SearchToolName:
		return d.search(ctx, req, params.Arguments)
	case GatewayCallToolName:
		return d.gatewayCall(ctx, req, params.Arguments, params.Meta)
	case AccessToolName:
		return d.access(ctx, req, params.Arguments)
	case QueryToolName, ExecuteToolName:
		return d.runProgram(ctx, req, params.Name, params.Arguments)
	}
	if params.Name == CallToolName && d.inventory != nil {
		return d.callThrough(ctx, req, params.Arguments, params.Meta)
	}
	if d.connections != nil && d.connections.Handles(params.Name) {
		markMetaTool(ctx)
		if !metaToolsPermitted(req.consumer) {
			return nil, &ToolNotPermittedError{Tool: params.Name}
		}
		return d.connections.Call(ctx, req.consumer, req.baseURL, params.Name)
	}
	if d.inventory != nil && d.inventory.Handles(params.Name) {
		markMetaTool(ctx)
		if !metaToolsPermitted(req.consumer) {
			return nil, &ToolNotPermittedError{Tool: params.Name}
		}
		return d.inventory.Call(ctx, req.consumer, params.Name, params.Arguments)
	}
	if d.agents != nil && d.agents.Handles(params.Name) {
		// A call to an agent is real work the person asked for, counted like
		// a tool call; only the listing is the gateway's own.
		if params.Name == ListAgentsToolName {
			markMetaTool(ctx)
		}
		if req.consumer == nil || !consumerdomain.IsStoreConsumer(req.consumer.Consumer) {
			return nil, &ToolNotPermittedError{Tool: params.Name}
		}
		return d.agents.Call(ctx, params.Name, params.Arguments)
	}
	if d.store != nil && d.store.Handles(params.Name) {
		markMetaTool(ctx)
		if req.consumer == nil || !consumerdomain.IsStoreConsumer(req.consumer.Consumer) {
			return nil, &ToolNotPermittedError{Tool: params.Name}
		}
		return d.store.Call(ctx, req.consumer, req.baseURL, params.Name, params.Arguments)
	}
	result, reached, err := d.invokeTool(ctx, req, params.Name, params.Arguments, params.Meta)
	d.searchStats.called(ctx, req.consumer, callViaDirect, params.Name, reached, err)
	return result, err
}

// callThrough serves CallToolName: it calls the named tool exactly as a
// tools/call naming it would have, so the inner call is resolved, scoped,
// guarded, audited and counted as that tool — the wrapper itself is not a tool
// the user has and leaves no trace of its own. Only a call-through that never
// reaches a tool is marked as the gateway's own.
//
// What the caller got wrong comes back as a tool error rather than a protocol
// one: the model wrote the arguments, and it is the one that can fix them.
func (d *RPCDispatcher) callThrough(
	ctx context.Context,
	req dispatchRequest,
	arguments, meta json.RawMessage,
) (any, error) {
	if !metaToolsPermitted(req.consumer) {
		markMetaTool(ctx)
		return nil, &ToolNotPermittedError{Tool: CallToolName}
	}
	args, err := decodeCallToolArgs(arguments)
	if err != nil {
		markMetaTool(ctx)
		return toolErrorResult(
			CallToolName+" takes {\"name\": <tool name>, \"arguments\": {…}}, and these arguments could not be read as that. Fix them and call again.",
			map[string]any{"error": "invalid_arguments"},
		)
	}
	if args.Name == "" {
		markMetaTool(ctx)
		return toolErrorResult(
			CallToolName+" needs `name`: the exact name of the tool to call, as "+InventoryToolName+" lists it.",
			map[string]any{"error": "missing_name"},
		)
	}
	if IsCodeModeToolName(args.Name) {
		// A client that kept the tool list it fetched before Code Mode was
		// turned on has no trustgate_query of its own: the call-through is its
		// way to one.
		return d.runProgram(ctx, req, args.Name, args.Arguments)
	}
	if isGatewayToolName(args.Name) {
		markMetaTool(ctx)
		return toolErrorResult(
			args.Name+" is one of the gateway's own tools: call it directly, not through "+CallToolName+".",
			map[string]any{"error": "gateway_tool", "name": args.Name},
		)
	}
	result, reached, err := d.invokeTool(ctx, req, args.Name, args.Arguments, meta)
	d.searchStats.called(ctx, req.consumer, callViaCallThrough, args.Name, reached, err)
	return withSchemaOnFailure(args.Name, reached, result, err)
}

// toolInvocation is what a call reached: the tool it resolved to, and whether
// what came back is the upstream's own answer rather than one a policy stage
// gave in its place.
type toolInvocation struct {
	target   *ResolvedTool
	upstream bool
}

// invokeTool calls one of the caller's own tools: resolve it, run the request
// stages, call the upstream, run the response stages.
func (d *RPCDispatcher) invokeTool(
	ctx context.Context,
	req dispatchRequest,
	name string,
	arguments, meta json.RawMessage,
) (any, toolInvocation, error) {
	// The binding is fixed before any plugin sees the request, so the plan is
	// chosen for the real destination and a body rewrite cannot reroute the call.
	// A name nobody serves, a toolkit denial or a pending consent answers here,
	// before any stage runs.
	target, err := d.composer.Resolve(ctx, req.consumer, name)
	if err != nil {
		return nil, toolInvocation{}, err
	}
	return d.invokeResolved(ctx, req, target, arguments, meta)
}

// invokeResolved calls a tool already resolved: the request stages, the
// upstream, the response stages.
func (d *RPCDispatcher) invokeResolved(
	ctx context.Context,
	req dispatchRequest,
	target *ResolvedTool,
	arguments, meta json.RawMessage,
) (any, toolInvocation, error) {
	reached := toolInvocation{target: target}
	if span := trace.SpanFromContext(ctx); span != nil {
		annotateRegistry(span, target.Registry, target.Tool.Name)
		span.SetMCPToolRisk(target.Tool.Risk())
		span.SetLatency(0)
	}
	call := ToolCall{
		Exposed:          target.Exposed,
		Registry:         target.Registry,
		NativeTool:       target.Tool.Name,
		Arguments:        arguments,
		Plan:             planFor(ctx, req.consumer, target),
		ClientToolCallID: toolCallID(meta),
	}
	pre, err := d.plugins.PreRequest(ctx, req.consumer, call)
	if err != nil {
		return nil, reached, err
	}
	if pre != nil {
		if pre.Result != nil {
			return pre.Result, reached, nil
		}
		if pre.Arguments != nil {
			call.Arguments = pre.Arguments
		}
	}
	result, err := d.composer.Invoke(ctx, req.consumer, target, call.Arguments)
	reached.upstream = true
	if err != nil {
		return nil, reached, err
	}
	// The text block has to exist before response plugins run. TrustGuard
	// inspects text blocks and the string values of structuredContent, not
	// object keys, so a keys-only payload would otherwise reach the model
	// as text no guard had seen. isError is left as it arrived.
	result = withStructuredContentText(result)
	post, err := d.plugins.PreResponse(ctx, req.consumer, call, result)
	if err != nil {
		// A response stage refused the answer: whatever it says, it is not
		// the upstream's word on the arguments.
		reached.upstream = false
		return nil, reached, err
	}
	if post != nil && post.Result != nil {
		result = post.Result
		reached.upstream = false
	}
	return result, reached, nil
}

// clientToolCallID reads the tool_call_id a caller volunteered in
// params._meta. Anything that is not a plain short token is dropped rather
// than rejected: the id only ever suppresses a duplicate count, so a malformed
// one costs the caller its correlation, not its call. Keeping the character set
// closed also keeps the value safe to interpolate into a counter key, where a
// separator smuggled inside the id could otherwise land it in another key's
// namespace.
func clientToolCallID(meta json.RawMessage) string {
	if len(meta) == 0 {
		return ""
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(meta, &fields); err != nil {
		return ""
	}
	raw, ok := fields[toolCallIDMetaKey]
	if !ok {
		return ""
	}
	var id string
	if err := json.Unmarshal(raw, &id); err != nil {
		return ""
	}
	if id == "" || len(id) > maxToolCallIDLen || !isToolCallIDToken(id) {
		return ""
	}
	return id
}

// toolCallID is the id of the tool call a caller volunteered in params._meta:
// the gateway's own key (clientToolCallID), else the first usable key an agent
// already sends (agentToolCallIDMetaKeys), held to the same rule.
func toolCallID(meta json.RawMessage) string {
	if id := clientToolCallID(meta); id != "" {
		return id
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(meta, &fields); err != nil {
		return ""
	}
	for _, key := range agentToolCallIDMetaKeys {
		var id string
		if err := json.Unmarshal(fields[key], &id); err != nil {
			continue
		}
		if id != "" && len(id) <= maxToolCallIDLen && isToolCallIDToken(id) {
			return id
		}
	}
	return ""
}

func isToolCallIDToken(id string) bool {
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// planFor picks the stage plan for a resolved destination. Consumers without
// precompiled MCP plans get nil, which makes the runner fall back to the
// consumer-wide plan exactly as before scopes existed. With a span recording,
// the same plan comes from Explain and the scope decision is stamped on the
// span next to the upstream; without one, PlanFor runs and nothing is
// allocated for a decision nobody would read.
func planFor(ctx context.Context, rc *appconsumer.RoutableConsumer, target *ResolvedTool) *appplugins.StagePlan {
	if rc == nil || rc.MCPPlans == nil {
		return nil
	}
	principal := identity.PrincipalFromContext(ctx)
	span := trace.SpanFromContext(ctx)
	if span == nil {
		return rc.MCPPlans.PlanFor(target.Registry, target.Tool.Name, principal)
	}
	plan, decision := rc.MCPPlans.Explain(target.Registry, target.Tool.Name, principal)
	span.SetMCPPolicyScope(policyScopeAttrs(decision))
	return plan
}

func policyScopeAttrs(decision appconsumer.ScopeDecision) trace.MCPPolicyScope {
	scope := trace.MCPPolicyScope{Evaluated: decision.Evaluated}
	if len(decision.Matched) > 0 {
		scope.Matched = make([]string, 0, len(decision.Matched))
		for _, ref := range decision.Matched {
			scope.Matched = append(scope.Matched, ref.ID)
		}
	}
	if len(decision.Skipped) > 0 {
		scope.Skipped = make([]trace.MCPSkippedPolicy, 0, len(decision.Skipped))
		for _, skipped := range decision.Skipped {
			scope.Skipped = append(scope.Skipped, trace.MCPSkippedPolicy{
				ID: skipped.ID, Name: skipped.Name, Reason: string(skipped.Reason),
			})
		}
	}
	return scope
}

func (d *RPCDispatcher) listResources(ctx context.Context, req dispatchRequest) (any, error) {
	if err := d.checkRateLimit(ctx, req.consumer); err != nil {
		return nil, err
	}
	resources, err := d.composer.ListResources(ctx, req.consumer)
	if err != nil {
		if !emptySurfaceInsteadOfError(ctx, req.consumer, err) {
			return nil, err
		}
		resources = nil
	}
	if resources == nil {
		resources = []Resource{}
	}
	return map[string]any{"resources": resources}, nil
}

func (d *RPCDispatcher) listResourceTemplates(ctx context.Context, req dispatchRequest) (any, error) {
	if err := d.checkRateLimit(ctx, req.consumer); err != nil {
		return nil, err
	}
	templates, err := d.composer.ListResourceTemplates(ctx, req.consumer)
	if err != nil {
		if !emptySurfaceInsteadOfError(ctx, req.consumer, err) {
			return nil, err
		}
		templates = nil
	}
	if templates == nil {
		templates = []ResourceTemplate{}
	}
	return map[string]any{"resourceTemplates": templates}, nil
}

func (d *RPCDispatcher) readResource(ctx context.Context, req dispatchRequest) (any, error) {
	var params struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(req.params, &params); err != nil || params.URI == "" {
		return nil, &InvalidParamsError{Reason: "resources/read requires params.uri"}
	}
	if err := d.checkRateLimit(ctx, req.consumer); err != nil {
		return nil, err
	}
	return d.composer.ReadResource(ctx, req.consumer, params.URI)
}

func (d *RPCDispatcher) listPrompts(ctx context.Context, req dispatchRequest) (any, error) {
	if err := d.checkRateLimit(ctx, req.consumer); err != nil {
		return nil, err
	}
	prompts, err := d.composer.ListPrompts(ctx, req.consumer)
	if err != nil {
		if !emptySurfaceInsteadOfError(ctx, req.consumer, err) {
			return nil, err
		}
		prompts = nil
	}
	if prompts == nil {
		prompts = []Prompt{}
	}
	return map[string]any{"prompts": prompts}, nil
}

func (d *RPCDispatcher) getPrompt(ctx context.Context, req dispatchRequest) (any, error) {
	var params struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments,omitempty"`
	}
	if err := json.Unmarshal(req.params, &params); err != nil || params.Name == "" {
		return nil, &InvalidParamsError{Reason: "prompts/get requires params.name"}
	}
	if err := d.checkRateLimit(ctx, req.consumer); err != nil {
		return nil, err
	}
	return d.composer.GetPrompt(ctx, req.consumer, params.Name, params.Arguments)
}

func (d *RPCDispatcher) checkRateLimit(ctx context.Context, consumer *appconsumer.RoutableConsumer) error {
	if consumer == nil || consumer.Consumer == nil {
		return nil
	}
	err := d.limiter.Check(ctx, consumer.Consumer.GatewayID)
	if err == nil {
		return nil
	}
	var exceeded *ratelimitapp.Exceeded
	if errors.As(err, &exceeded) {
		return &RPCError{
			Code: CodeRateLimited, Message: exceeded.Error(),
			Data: json.RawMessage(exceeded.Body()), HTTPHeaders: exceeded.Headers(),
		}
	}
	if errors.Is(err, ratelimitapp.ErrUnavailable) {
		return &RPCError{Code: CodeUnavailable, Message: err.Error()}
	}
	return err
}

func appendGatewayTools(tools []Tool, gatewayTools []Tool) []Tool {
	for _, gatewayTool := range gatewayTools {
		matched := false
		for i := range tools {
			if tools[i].Name == gatewayTool.Name {
				tools[i] = gatewayTool
				matched = true
				break
			}
		}
		if !matched {
			tools = append(tools, gatewayTool)
		}
	}
	return tools
}

// MetaToolsPermitted reports whether the gateway adds its own tools — the
// inventory and the call-through among them — to this consumer's surface, so
// text that points at them is only said where they are.
func MetaToolsPermitted(consumer *appconsumer.RoutableConsumer) bool {
	return metaToolsPermitted(consumer)
}

// metaToolsPermitted reports whether the gateway may add its own tools to this
// consumer's surface. A consumer carrying a toolkit that names no tool at all is
// deny-all: it is meant to expose nothing, so the gateway adds nothing either —
// not a connect link, and not an inventory that would name the servers behind
// the empty surface. Every other consumer gets them.
func metaToolsPermitted(consumer *appconsumer.RoutableConsumer) bool {
	if consumer == nil || consumer.Consumer == nil {
		return false
	}
	toolkit := consumer.Consumer.Toolkit()
	if toolkit == nil {
		return true
	}
	for _, entry := range toolkit {
		if entry.Tool != "" {
			return true
		}
	}
	return false
}
