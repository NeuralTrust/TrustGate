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
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

var ErrMethodNotFound = errors.New("mcp: method not found")

// toolCallIDMetaKey is the params._meta key an agent uses to tell the gateway
// which LLM tool_call_id a tools/call is executing, so a policy watching both
// protocols counts the execution once (ENG-1579). The reverse-DNS prefix keeps
// it out of the way of the keys the MCP spec reserves.
const toolCallIDMetaKey = "ai.neuraltrust/toolCallId"

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
	storeScoper appstore.Scoper
	handlers    map[string]rpcHandler
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

func emptySurfaceInsteadOfError(consumer *appconsumer.RoutableConsumer, err error) bool {
	if _, ok := errors.AsType[*ConsentRequiredError](err); ok {
		return true
	}
	perUser := consumer != nil && consumer.Consumer != nil &&
		(consumerdomain.IsStoreConsumer(consumer.Consumer) || consumer.Consumer.ActsForUsers())
	return perUser && (errors.Is(err, ErrNoMCPRegistries) || errors.Is(err, ErrUpstreamUnavailable))
}

func (d *RPCDispatcher) listTools(ctx context.Context, req dispatchRequest) (any, error) {
	if err := d.checkRateLimit(ctx, req.consumer); err != nil {
		return nil, err
	}
	tools, err := d.composer.ListTools(ctx, req.consumer)
	if err != nil {
		if !emptySurfaceInsteadOfError(req.consumer, err) {
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
	if d.connections != nil && metaToolsPermitted(req.consumer) {
		tools = appendGatewayTools(tools, d.connections.Definitions(ctx, req.consumer))
	}
	if d.store != nil && req.consumer != nil && req.consumer.Consumer != nil && consumerdomain.IsStoreConsumer(req.consumer.Consumer) {
		tools = appendGatewayTools(tools, d.store.Definitions(ctx, req.consumer))
	}
	if d.inventory != nil && metaToolsPermitted(req.consumer) {
		tools = appendGatewayTools(tools, d.inventory.Definitions(ctx, req.consumer))
	}
	result["tools"] = tools
	return result, nil
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
	if d.connections != nil && d.connections.Handles(params.Name) {
		if !metaToolsPermitted(req.consumer) {
			return nil, &ToolNotPermittedError{Tool: params.Name}
		}
		return d.connections.Call(ctx, req.consumer, req.baseURL, params.Name)
	}
	if d.inventory != nil && d.inventory.Handles(params.Name) {
		if !metaToolsPermitted(req.consumer) {
			return nil, &ToolNotPermittedError{Tool: params.Name}
		}
		return d.inventory.Call(ctx, req.consumer, params.Name, params.Arguments)
	}
	if d.store != nil && d.store.Handles(params.Name) {
		if req.consumer == nil || !consumerdomain.IsStoreConsumer(req.consumer.Consumer) {
			return nil, &ToolNotPermittedError{Tool: params.Name}
		}
		return d.store.Call(ctx, req.consumer, req.baseURL, params.Name, params.Arguments)
	}
	// The binding is fixed before any plugin sees the request, so the plan is
	// chosen for the real destination and a body rewrite cannot reroute the call.
	// A name nobody serves, a toolkit denial or a pending consent answers here,
	// before any stage runs.
	target, err := d.composer.Resolve(ctx, req.consumer, params.Name)
	if err != nil {
		return nil, err
	}
	call := ToolCall{
		Exposed:          target.Exposed,
		Registry:         target.Registry,
		NativeTool:       target.Tool.Name,
		Arguments:        params.Arguments,
		Plan:             planFor(ctx, req.consumer, target),
		ClientToolCallID: clientToolCallID(params.Meta),
	}
	pre, err := d.plugins.PreRequest(ctx, req.consumer, call)
	if err != nil {
		return nil, err
	}
	if pre != nil {
		if pre.Result != nil {
			return pre.Result, nil
		}
		if pre.Arguments != nil {
			call.Arguments = pre.Arguments
		}
	}
	result, err := d.composer.Invoke(ctx, req.consumer, target, call.Arguments)
	if err != nil {
		return nil, err
	}
	post, err := d.plugins.PreResponse(ctx, req.consumer, call, result)
	if err != nil {
		return nil, err
	}
	if post != nil && post.Result != nil {
		result = post.Result
	}
	return result, nil
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
		if !emptySurfaceInsteadOfError(req.consumer, err) {
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
		if !emptySurfaceInsteadOfError(req.consumer, err) {
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
		if !emptySurfaceInsteadOfError(req.consumer, err) {
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
