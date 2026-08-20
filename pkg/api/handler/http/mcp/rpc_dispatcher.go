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

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

var (
	ErrMethodNotFound          = errors.New("mcp: method not found")
	errMalformedAppsCapability = errors.New("mcp: malformed Apps capability")
)

type InvalidParamsError struct {
	Reason string
}

func (e *InvalidParamsError) Error() string { return "mcp: invalid params: " + e.Reason }

// DefaultMaxContinuationBytes caps the multi round-trip payload a client may
// echo back on tools/call.
const DefaultMaxContinuationBytes = 256 * 1024

type RPCGateway struct {
	composer             appmcp.Composer
	plugins              *appmcp.PluginRunner
	limiter              ratelimitapp.Checker
	appsListPolicy       appmcp.AppsListPolicy
	appsReadPolicy       appmcp.AppsReadPolicy
	appsRecorder         AppsRecorder
	maxContinuationBytes int
}

// NewRPCGateway wires MCP dispatch; nil limiter defaults to noop.
func NewRPCGateway(composer appmcp.Composer, plugins *appmcp.PluginRunner, limiter ratelimitapp.Checker) *RPCGateway {
	return NewRPCGatewayWithLimits(composer, plugins, limiter, DefaultMaxContinuationBytes)
}

// NewRPCGatewayWithLimits wires MCP dispatch with an explicit continuation cap.
func NewRPCGatewayWithLimits(
	composer appmcp.Composer,
	plugins *appmcp.PluginRunner,
	limiter ratelimitapp.Checker,
	maxContinuationBytes int,
) *RPCGateway {
	return NewRPCGatewayWithAppsPolicies(
		composer,
		plugins,
		limiter,
		appmcp.AppsListPolicy{},
		appmcp.AppsReadPolicy{},
		maxContinuationBytes,
	)
}

// NewRPCGatewayWithAppsListPolicy wires MCP dispatch with explicit Apps list and continuation policies.
func NewRPCGatewayWithAppsListPolicy(
	composer appmcp.Composer,
	plugins *appmcp.PluginRunner,
	limiter ratelimitapp.Checker,
	appsListPolicy appmcp.AppsListPolicy,
	maxContinuationBytes int,
) *RPCGateway {
	return NewRPCGatewayWithAppsPolicies(
		composer,
		plugins,
		limiter,
		appsListPolicy,
		appmcp.AppsReadPolicy{},
		maxContinuationBytes,
	)
}

// NewRPCGatewayWithAppsPolicies wires MCP dispatch with explicit Apps and continuation policies.
func NewRPCGatewayWithAppsPolicies(
	composer appmcp.Composer,
	plugins *appmcp.PluginRunner,
	limiter ratelimitapp.Checker,
	appsListPolicy appmcp.AppsListPolicy,
	appsReadPolicy appmcp.AppsReadPolicy,
	maxContinuationBytes int,
	recorders ...AppsRecorder,
) *RPCGateway {
	if limiter == nil {
		limiter = ratelimitapp.NewNoopChecker()
	}
	if maxContinuationBytes <= 0 {
		maxContinuationBytes = DefaultMaxContinuationBytes
	}
	var appsRecorder AppsRecorder
	if len(recorders) > 0 {
		appsRecorder = recorders[0]
	}
	return &RPCGateway{
		composer:             composer,
		plugins:              plugins,
		limiter:              limiter,
		appsListPolicy:       appsListPolicy,
		appsReadPolicy:       appsReadPolicy,
		appsRecorder:         appsRecorder,
		maxContinuationBytes: maxContinuationBytes,
	}
}

func validateContinuationSize(inputResponses json.RawMessage, requestState string, limit int) error {
	if limit <= 0 {
		limit = DefaultMaxContinuationBytes
	}
	if len(inputResponses)+len(requestState) > limit {
		return &InvalidParamsError{Reason: "tools/call continuation exceeds the maximum size"}
	}
	if len(inputResponses) == 0 {
		return nil
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(inputResponses, &shape); err != nil {
		return &InvalidParamsError{Reason: "tools/call inputResponses must be an object"}
	}
	return nil
}

func (g *RPCGateway) Dispatch(ctx context.Context, rc *appconsumer.RoutableConsumer, method string, params json.RawMessage) (any, error) {
	span, ctx := g.startSpan(ctx, method, params)
	result, err := g.dispatch(ctx, rc, method, params)
	g.finishSpan(span, err)
	return result, err
}

// OpenSubscriptionLease runs the gateway-side admission work a lease is charged
// for. Tools subscriptions must pass the same discovery plugin verdict as an
// ordinary tools/list before registry capacity is claimed.
func (g *RPCGateway) OpenSubscriptionLease(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	honoured appmcp.HonouredSet,
) error {
	span, ctx := g.startSpan(ctx, appmcp.MethodSubscriptionsListen, nil)
	err := g.checkRateLimit(ctx, rc)
	if err == nil && honoured.Has(appmcp.NotificationToolsListChanged) {
		var tools []appmcp.Tool
		tools, err = g.composer.ListTools(ctx, rc)
		if err == nil {
			tools, err = g.filterAppsTools(ctx, rc, tools)
		}
		if err == nil {
			err = g.plugins.PreResponseToolsDiscovery(ctx, rc, tools)
		}
	}
	g.finishSpan(span, err)
	return err
}

func (g *RPCGateway) startSpan(ctx context.Context, method string, params json.RawMessage) (*trace.Span, context.Context) {
	rt := trace.FromContext(ctx)
	if rt == nil {
		return nil, ctx
	}
	span := rt.StartSpan(trace.SpanMCP, method)
	operation, tool, prompt, resourceURI := mcpRequestAttrs(method, params)
	span.SetMCPRequest(method, operation, tool, prompt, resourceURI)
	stampMCPProtocol(span, ctx)
	return span, trace.NewSpanContext(ctx, span)
}

func (g *RPCGateway) finishSpan(span *trace.Span, err error) {
	if span == nil {
		return
	}
	defer span.End()
	if err == nil {
		span.SetMCPStatus(http.StatusOK, 0)
		return
	}
	span.SetError(err.Error())
	var (
		rpcErr       *appmcp.RPCError
		consentErr   *appmcp.ConsentRequiredError
		notPermitted *appmcp.ToolNotPermittedError
	)
	switch {
	case errors.As(err, &rpcErr):
		span.SetMCPStatus(rpcErr.ResolvedHTTPStatus(), int(rpcErr.Code))
	case errors.As(err, &consentErr):
		// Both of these answer HTTP 200 on the wire so MCP clients parse the
		// JSON-RPC error instead of tearing down the transport. The status the
		// refusal *means* belongs in telemetry, which is what this records:
		// otherwise an unconnected upstream showed up as a 502 and buried real
		// upstream failures among routine consent prompts.
		span.SetMCPStatus(http.StatusForbidden, codeConsentRequired)
	case errors.As(err, &notPermitted):
		span.SetMCPStatus(http.StatusForbidden, codePolicyBlocked)
	case errors.Is(err, appmcp.ErrToolNotFound), errors.Is(err, appmcp.ErrPromptNotFound),
		errors.Is(err, appmcp.ErrResourceNotFound):
		span.SetMCPStatus(http.StatusNotFound, 0)
	default:
		span.SetMCPStatus(http.StatusBadGateway, 0)
	}
}

// mcpRequestAttrs derives the operation classification and the parsed
// tool/prompt/resource identifiers from the JSON-RPC method and params.
func mcpRequestAttrs(method string, params json.RawMessage) (operation, tool, prompt, resourceURI string) {
	switch method {
	case "tools/list":
		return "discovery", "", "", ""
	case "tools/call":
		var p struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(params, &p)
		return "tool", p.Name, "", ""
	case "resources/list", "resources/templates/list":
		return "discovery", "", "", ""
	case "resources/read":
		var p struct {
			URI string `json:"uri"`
		}
		_ = json.Unmarshal(params, &p)
		return "resource", "", "", p.URI
	case "prompts/list":
		return "discovery", "", "", ""
	case "prompts/get":
		var p struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(params, &p)
		return "prompt", "", p.Name, ""
	case appmcp.MethodTasksGet, appmcp.MethodTasksUpdate, appmcp.MethodTasksCancel:
		// The tool the task belongs to is only known once the handle is
		// unwrapped, and the handle itself is never an attribute.
		return "task", "", "", ""
	case appmcp.MethodSubscriptionsListen:
		// Neither the subscription id nor any requested URI is ever an attribute.
		return "subscription", "", "", ""
	default:
		return "", "", "", ""
	}
}

func (g *RPCGateway) checkRateLimit(ctx context.Context, rc *appconsumer.RoutableConsumer) error {
	if rc == nil || rc.Consumer == nil {
		return nil
	}
	err := g.limiter.Check(ctx, rc.Consumer.GatewayID)
	if err == nil {
		return nil
	}
	var exceeded *ratelimitapp.Exceeded
	if errors.As(err, &exceeded) {
		return &appmcp.RPCError{
			Code:        appmcp.CodeRateLimited,
			Message:     exceeded.Error(),
			Data:        json.RawMessage(exceeded.Body()),
			HTTPHeaders: exceeded.Headers(),
		}
	}
	if errors.Is(err, ratelimitapp.ErrUnavailable) {
		return &appmcp.RPCError{
			Code:    appmcp.CodeUnavailable,
			Message: err.Error(),
		}
	}
	return err
}

func (g *RPCGateway) dispatch(ctx context.Context, rc *appconsumer.RoutableConsumer, method string, params json.RawMessage) (any, error) {
	switch method {
	case "tools/list":
		if err := g.checkRateLimit(ctx, rc); err != nil {
			return nil, err
		}
		tools, err := g.composer.ListTools(ctx, rc)
		if err != nil {
			return nil, err
		}
		before := len(tools)
		tools, err = g.filterAppsTools(ctx, rc, tools)
		if err != nil {
			return nil, err
		}
		g.recordApps(ctx, "tools_list", "dropped", before-len(tools))
		if tools == nil {
			tools = []appmcp.Tool{}
		}
		if err := g.plugins.PreResponseToolsDiscovery(ctx, rc, tools); err != nil {
			return nil, err
		}
		return map[string]any{"tools": tools}, nil
	case "tools/call":
		var p struct {
			Name           string          `json:"name"`
			Arguments      json.RawMessage `json:"arguments,omitempty"`
			InputResponses json.RawMessage `json:"inputResponses,omitempty"`
			RequestState   string          `json:"requestState,omitempty"`
		}
		if err := json.Unmarshal(params, &p); err != nil || p.Name == "" {
			return nil, &InvalidParamsError{Reason: "tools/call requires params.name"}
		}
		if err := validateContinuationSize(p.InputResponses, p.RequestState, g.maxContinuationBytes); err != nil {
			return nil, err
		}
		// Every round runs the full policy pass: rate limits, plugins, and the
		// composer's toolkit check. A continuation is never a shortcut past them.
		if err := g.checkRateLimit(ctx, rc); err != nil {
			return nil, err
		}
		pre, err := g.plugins.PreRequest(ctx, rc, p.Name, p.Arguments, p.InputResponses)
		if err != nil {
			return nil, err
		}
		// The request stage may rewrite the tool input (data-masking) or answer
		// the call outright. Carry both forward: reusing the original arguments
		// would send upstream exactly what a plugin just redacted.
		call := appmcp.ToolCall{
			Name:           p.Name,
			Arguments:      p.Arguments,
			InputResponses: p.InputResponses,
			RequestState:   p.RequestState,
		}
		if pre != nil {
			if pre.Result != nil {
				if _, err := g.appsReadPolicy.ValidateCallResult(pre.Result); err != nil {
					return nil, g.mapAppsRejection(ctx, "call", err)
				}
				return pre.Result, nil
			}
			if pre.Arguments != nil {
				call.Arguments = pre.Arguments
			}
			if pre.InputResponses != nil {
				call.InputResponses = pre.InputResponses
			}
		}
		result, appsCall, err := g.callTool(ctx, rc, call)
		if err != nil {
			return nil, g.mapAppsRejection(ctx, "call", err)
		}
		post, err := g.plugins.PreResponse(ctx, rc, p.Name, call.Arguments, result)
		if err != nil {
			return nil, err
		}
		if post != nil && post.Result != nil {
			result = post.Result
		}
		if _, err := g.appsReadPolicy.ValidateCallResult(result, appsCall); err != nil {
			return nil, g.mapAppsRejection(ctx, "call", err)
		}
		return result, nil
	case "resources/list":
		if err := g.checkRateLimit(ctx, rc); err != nil {
			return nil, err
		}
		resources, err := g.composer.ListResources(ctx, rc)
		if err != nil {
			return nil, err
		}
		before := len(resources)
		resources, _ = g.appsListPolicy.FilterResources(resources)
		g.recordApps(ctx, "resources_list", "dropped", before-len(resources))
		if resources == nil {
			resources = []appmcp.Resource{}
		}
		return map[string]any{"resources": resources}, nil
	case "resources/templates/list":
		if err := g.checkRateLimit(ctx, rc); err != nil {
			return nil, err
		}
		templates, err := g.composer.ListResourceTemplates(ctx, rc)
		if err != nil {
			return nil, err
		}
		before := len(templates)
		templates, _ = g.appsListPolicy.FilterResourceTemplates(templates)
		g.recordApps(ctx, "templates_list", "dropped", before-len(templates))
		if templates == nil {
			templates = []appmcp.ResourceTemplate{}
		}
		return map[string]any{"resourceTemplates": templates}, nil
	case "resources/read":
		var p struct {
			URI string `json:"uri"`
		}
		if err := json.Unmarshal(params, &p); err != nil || p.URI == "" {
			return nil, &InvalidParamsError{Reason: "resources/read requires params.uri"}
		}
		appsRead := g.appsReadPolicy.RequiresValidation(p.URI)
		if appsRead {
			protocol, _ := ctx.Value(mcpProtocolContextKey{}).(mcpProtocolAttrs)
			if protocol.era != eraLabel(protocolEraModern) &&
				requestMetadataProtocolVersion(params).value != modernProtocolVersion {
				return nil, g.mapAppsRejection(ctx, "read", appmcp.ErrAppsResourceRejected)
			}
			capability, err := declaredMCPAppsCapability(rawClientCapabilities(params))
			if err != nil {
				g.recordApps(ctx, "read", "rejected", 1)
				return nil, errMalformedAppsCapability
			}
			if err := g.appsReadPolicy.ValidateReadRequest(p.URI, capability); err != nil {
				return nil, g.mapAppsRejection(ctx, "read", err)
			}
		}
		if err := g.checkRateLimit(ctx, rc); err != nil {
			return nil, err
		}
		if appsRead && g.appsListPolicy.Enabled() {
			resources, err := g.composer.ListResources(ctx, rc)
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				return nil, g.mapAppsRejection(ctx, "read", appmcp.ErrAppsResourceRejected)
			}
			resources, _ = g.appsListPolicy.FilterResources(resources)
			if err := g.appsListPolicy.ValidateReadBinding(p.URI, resources); err != nil {
				return nil, g.mapAppsRejection(ctx, "read", err)
			}
		}
		result, err := g.composer.ReadResource(ctx, rc, p.URI)
		if err != nil {
			return nil, err
		}
		if !appsRead {
			return result, nil
		}
		result, err = g.appsReadPolicy.ValidateReadResult(p.URI, result)
		if err != nil {
			return nil, g.mapAppsRejection(ctx, "read", err)
		}
		return appmcp.AppsReadResult(result), nil
	case "prompts/list":
		if err := g.checkRateLimit(ctx, rc); err != nil {
			return nil, err
		}
		prompts, err := g.composer.ListPrompts(ctx, rc)
		if err != nil {
			return nil, err
		}
		if prompts == nil {
			prompts = []appmcp.Prompt{}
		}
		return map[string]any{"prompts": prompts}, nil
	case "prompts/get":
		var p struct {
			Name      string            `json:"name"`
			Arguments map[string]string `json:"arguments,omitempty"`
		}
		if err := json.Unmarshal(params, &p); err != nil || p.Name == "" {
			return nil, &InvalidParamsError{Reason: "prompts/get requires params.name"}
		}
		if err := g.checkRateLimit(ctx, rc); err != nil {
			return nil, err
		}
		return g.composer.GetPrompt(ctx, rc, p.Name, p.Arguments)
	case appmcp.MethodTasksGet, appmcp.MethodTasksUpdate, appmcp.MethodTasksCancel:
		return g.dispatchTask(ctx, rc, method, params)
	default:
		return nil, fmt.Errorf("%w: %s", ErrMethodNotFound, method)
	}
}

func (g *RPCGateway) filterAppsTools(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	tools []appmcp.Tool,
) ([]appmcp.Tool, error) {
	tools, _ = g.appsListPolicy.FilterTools(tools)
	if !g.appsListPolicy.HasToolResourceReferences(tools) {
		return tools, nil
	}
	resources, err := g.composer.ListResources(ctx, rc)
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	resources, _ = g.appsListPolicy.FilterResources(resources)
	tools, _ = g.appsListPolicy.FilterToolsWithResources(tools, resources)
	return tools, nil
}

func (g *RPCGateway) callTool(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	call appmcp.ToolCall,
) (json.RawMessage, bool, error) {
	if g.appsListPolicy.Enabled() {
		if composer, ok := g.composer.(appmcp.AppsCallComposer); ok {
			return composer.CallToolClassified(ctx, rc, call)
		}
	}
	result, err := g.composer.CallTool(ctx, rc, call)
	return result, false, err
}

func (g *RPCGateway) mapAppsRejection(ctx context.Context, operation string, err error) error {
	if errors.Is(err, appmcp.ErrAppsResourceRejected) ||
		errors.Is(err, appmcp.ErrInvalidAppsDocument) ||
		errors.Is(err, appmcp.ErrInvalidAppsMetadata) {
		g.recordApps(ctx, operation, "rejected", 1)
	}
	return appmcp.MapAppsReadError(err)
}

func (g *RPCGateway) recordApps(ctx context.Context, operation, outcome string, count int) {
	if g.appsRecorder != nil && count > 0 {
		g.appsRecorder.Record(ctx, operation, outcome, int64(count))
	}
}
