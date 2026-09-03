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
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

var ErrMethodNotFound = errors.New("mcp: method not found")

type InvalidParamsError struct {
	Reason string
}

func (e *InvalidParamsError) Error() string { return "mcp: invalid params: " + e.Reason }

type RPCGateway struct {
	composer    appmcp.Composer
	plugins     *appmcp.PluginRunner
	limiter     ratelimitapp.Checker
	connections appmcp.ConnectionTool
	store       appmcp.StoreTool
	storeScoper appstore.Scoper
}

// NewRPCGateway wires MCP dispatch; nil limiter defaults to noop.
func NewRPCGateway(composer appmcp.Composer, plugins *appmcp.PluginRunner, limiter ratelimitapp.Checker) *RPCGateway {
	if limiter == nil {
		limiter = ratelimitapp.NewNoopChecker()
	}
	return &RPCGateway{composer: composer, plugins: plugins, limiter: limiter}
}

// NewRPCGatewayWithConnections wires the optional TrustGate connection-management tool.
func NewRPCGatewayWithConnections(
	composer appmcp.Composer,
	plugins *appmcp.PluginRunner,
	limiter ratelimitapp.Checker,
	connections appmcp.ConnectionTool,
) *RPCGateway {
	gateway := NewRPCGateway(composer, plugins, limiter)
	gateway.connections = connections
	return gateway
}

// NewRPCGatewayWithMetaTools wires both the connection-management tool and the
// MCP Store meta-tools (search / install / …).
func NewRPCGatewayWithMetaTools(
	composer appmcp.Composer,
	plugins *appmcp.PluginRunner,
	limiter ratelimitapp.Checker,
	connections appmcp.ConnectionTool,
	store appmcp.StoreTool,
) *RPCGateway {
	gateway := NewRPCGatewayWithConnections(composer, plugins, limiter, connections)
	gateway.store = store
	return gateway
}

// WithStoreScoper attaches the CatalogScoper so the Store surfaces the calling
// principal's installed servers. Returns the gateway for chaining.
func (g *RPCGateway) WithStoreScoper(scoper appstore.Scoper) *RPCGateway {
	g.storeScoper = scoper
	return g
}

func (g *RPCGateway) Dispatch(ctx context.Context, rc *appconsumer.RoutableConsumer, method string, params json.RawMessage) (any, error) {
	return g.DispatchWithBaseURL(ctx, rc, "", method, params)
}

// DispatchWithBaseURL dispatches an MCP request with the public origin used for user-facing links.
func (g *RPCGateway) DispatchWithBaseURL(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	baseURL,
	method string,
	params json.RawMessage,
) (any, error) {
	span, ctx := g.startSpan(ctx, method, params)
	result, err := g.dispatch(ctx, rc, baseURL, method, params)
	g.finishSpan(span, err)
	return result, err
}

func (g *RPCGateway) startSpan(ctx context.Context, method string, params json.RawMessage) (*trace.Span, context.Context) {
	rt := trace.FromContext(ctx)
	if rt == nil {
		return nil, ctx
	}
	span := rt.StartSpan(trace.SpanMCP, method)
	operation, tool, prompt, resourceURI := mcpRequestAttrs(method, params)
	span.SetMCPRequest(method, operation, tool, prompt, resourceURI)
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
	case errors.Is(err, ErrMethodNotFound):
		span.SetMCPStatus(http.StatusNotFound, codeMethodNotFound)
	default:
		span.SetMCPStatus(http.StatusBadGateway, 0)
	}
}

// mcpRequestAttrs derives the operation classification and the parsed
// tool/prompt/resource identifiers from the JSON-RPC method and params.
func mcpRequestAttrs(method string, params json.RawMessage) (operation, tool, prompt, resourceURI string) {
	switch method {
	case "server/discover":
		return "discovery", "", "", ""
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

func (g *RPCGateway) dispatch(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	baseURL,
	method string,
	params json.RawMessage,
) (any, error) {
	// Scope the Store to the caller's installed servers. The scoper no-ops for
	// any non-Store consumer; on a transient error we proceed with the meta-tools
	// only rather than failing the request.
	if g.storeScoper != nil {
		if scoped, err := g.storeScoper.Scope(ctx, rc); err == nil {
			rc = scoped
		}
	}
	switch method {
	case "tools/list":
		if err := g.checkRateLimit(ctx, rc); err != nil {
			return nil, err
		}
		isStore := rc != nil && rc.Consumer != nil && consumerdomain.IsStoreConsumer(rc.Consumer)
		tools, err := g.composer.ListTools(ctx, rc)
		if err != nil {
			// The synthetic Store consumer carries no registries of its own — its
			// tools are the gateway-implemented meta-tools appended below — so a
			// registry-less listing is empty for it, not an error. (Once servers are
			// installed the scoper attaches their registries and this no longer fires.)
			if isStore && errors.Is(err, appmcp.ErrNoMCPRegistries) {
				tools = nil
			} else {
				return nil, err
			}
		}
		if tools == nil {
			tools = []appmcp.Tool{}
		}
		result := map[string]any{"tools": tools}
		raw, err := json.Marshal(result)
		if err != nil {
			return nil, err
		}
		// A tool listing is static server metadata, so it is scanned only for
		// threats in the tool descriptions (indirect prompt injection, code
		// injection): a genuine block stops discovery, while a data-masking
		// transform is ignored — the listing is never redacted or rewritten.
		if err := g.plugins.PreResponseDiscovery(ctx, rc, raw); err != nil {
			return nil, err
		}
		if g.connections != nil && connectionToolPermitted(rc) {
			tools = appendGatewayTools(tools, g.connections.Definitions(ctx, rc))
		}
		if g.store != nil && isStore {
			tools = appendGatewayTools(tools, g.store.Definitions(ctx, rc))
		}
		result["tools"] = tools
		return result, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments,omitempty"`
		}
		if err := json.Unmarshal(params, &p); err != nil || p.Name == "" {
			return nil, &InvalidParamsError{Reason: "tools/call requires params.name"}
		}
		if err := g.checkRateLimit(ctx, rc); err != nil {
			return nil, err
		}
		if g.connections != nil && g.connections.Handles(p.Name) {
			if !connectionToolPermitted(rc) {
				return nil, &appmcp.ToolNotPermittedError{Tool: p.Name}
			}
			return g.connections.Call(ctx, rc, baseURL, p.Name)
		}
		if g.store != nil && g.store.Handles(p.Name) {
			if rc == nil || !consumerdomain.IsStoreConsumer(rc.Consumer) {
				return nil, &appmcp.ToolNotPermittedError{Tool: p.Name}
			}
			return g.store.Call(ctx, rc, p.Name, p.Arguments)
		}
		pre, err := g.plugins.PreRequest(ctx, rc, p.Name, p.Arguments)
		if err != nil {
			return nil, err
		}
		// The request stage may rewrite the tool input (data-masking) or answer
		// the call outright. Carry both forward: reusing the original arguments
		// would send upstream exactly what a plugin just redacted.
		arguments := p.Arguments
		if pre != nil {
			if pre.Result != nil {
				return pre.Result, nil
			}
			if pre.Arguments != nil {
				arguments = pre.Arguments
			}
		}
		result, err := g.composer.CallTool(ctx, rc, p.Name, arguments)
		if err != nil {
			return nil, err
		}
		post, err := g.plugins.PreResponse(ctx, rc, p.Name, arguments, result)
		if err != nil {
			return nil, err
		}
		if post != nil && post.Result != nil {
			result = post.Result
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
		if err := g.checkRateLimit(ctx, rc); err != nil {
			return nil, err
		}
		return g.composer.ReadResource(ctx, rc, p.URI)
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
	default:
		return nil, fmt.Errorf("%w: %s", ErrMethodNotFound, method)
	}
}

func appendGatewayTools(tools []appmcp.Tool, gatewayTools []appmcp.Tool) []appmcp.Tool {
	for _, gatewayTool := range gatewayTools {
		tools = appendGatewayTool(tools, gatewayTool)
	}
	return tools
}

func appendGatewayTool(tools []appmcp.Tool, gatewayTool appmcp.Tool) []appmcp.Tool {
	for i := range tools {
		if tools[i].Name == gatewayTool.Name {
			tools[i] = gatewayTool
			return tools
		}
	}
	return append(tools, gatewayTool)
}

func connectionToolPermitted(rc *appconsumer.RoutableConsumer) bool {
	if rc == nil || rc.Consumer == nil {
		return false
	}
	toolkit := rc.Consumer.Toolkit()
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
