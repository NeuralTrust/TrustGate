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
	connections          appmcp.ConnectionTool
	store                appmcp.StoreTool
	storeScoper          appstore.Scoper
	appsListPolicy       appmcp.AppsListPolicy
	appsReadPolicy       appmcp.AppsReadPolicy
	appsRecorder         AppsRecorder
	maxContinuationBytes int
}

// GatewayOption configures optional RPCGateway collaborators without widening
// the constructor for the common case. Every option is independent, so a caller
// asks for exactly the capabilities it needs instead of picking the constructor
// whose fixed parameter list happens to match.
type GatewayOption func(*RPCGateway)

// WithMaxContinuationBytes caps the mediated continuation payload a tools/call
// may carry (inputResponses plus requestState). A non-positive value keeps
// DefaultMaxContinuationBytes.
func WithMaxContinuationBytes(maxContinuationBytes int) GatewayOption {
	return func(g *RPCGateway) {
		if maxContinuationBytes > 0 {
			g.maxContinuationBytes = maxContinuationBytes
		}
	}
}

// WithAppsListPolicy filters marked secure-Apps metadata out of tool, resource
// and template listings. A zero policy leaves Apps filtering off, which is the
// default a gateway is built with.
func WithAppsListPolicy(list appmcp.AppsListPolicy) GatewayOption {
	return func(g *RPCGateway) { g.appsListPolicy = list }
}

// WithAppsPolicies enforces both secure-Apps policies — listing and resource
// read — and reports Apps outcomes to the recorder. It supersedes
// WithAppsListPolicy rather than composing with it.
func WithAppsPolicies(
	list appmcp.AppsListPolicy,
	read appmcp.AppsReadPolicy,
	recorder AppsRecorder,
) GatewayOption {
	return func(g *RPCGateway) {
		g.appsListPolicy = list
		g.appsReadPolicy = read
		g.appsRecorder = recorder
	}
}

// WithConnections wires the TrustGate connection-management tool, whose
// per-provider connect tools the gateway appends to a listing.
func WithConnections(connections appmcp.ConnectionTool) GatewayOption {
	return func(g *RPCGateway) { g.connections = connections }
}

// WithStoreTool wires the MCP Store meta-tools (search / install / …).
func WithStoreTool(store appmcp.StoreTool) GatewayOption {
	return func(g *RPCGateway) { g.store = store }
}

// WithStoreScoper attaches the CatalogScoper so the Store surfaces the calling
// principal's installed servers.
func WithStoreScoper(scoper appstore.Scoper) GatewayOption {
	return func(g *RPCGateway) { g.storeScoper = scoper }
}

// NewRPCGateway wires MCP dispatch; nil limiter defaults to noop.
func NewRPCGateway(
	composer appmcp.Composer,
	plugins *appmcp.PluginRunner,
	limiter ratelimitapp.Checker,
	opts ...GatewayOption,
) *RPCGateway {
	if limiter == nil {
		limiter = ratelimitapp.NewNoopChecker()
	}
	g := &RPCGateway{
		composer:             composer,
		plugins:              plugins,
		limiter:              limiter,
		maxContinuationBytes: DefaultMaxContinuationBytes,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(g)
		}
	}
	return g
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
			// The gateway's own tools — the Store meta-tools and the per-provider
			// connect tools appended below — are exactly how a user installs a
			// server or connects an account. An upstream problem must never hide
			// them, so these list-time errors degrade to an empty upstream list
			// rather than failing the whole listing:
			//   - the synthetic Store consumer carries no registries of its own
			//     until servers are installed (ErrNoMCPRegistries), and its installed
			//     servers may be unreachable — either way its meta-tools still list;
			//   - any consumer whose bound upstreams are all still pending the user's
			//     connection (ConsentRequiredError) must still be shown the connect
			//     tools; a tool call, not the listing, is where consent is reported.
			var consentErr *appmcp.ConsentRequiredError
			switch {
			case isStore && errors.Is(err, appmcp.ErrNoMCPRegistries):
				tools = nil
			case isStore && errors.Is(err, appmcp.ErrUpstreamUnavailable):
				tools = nil
			case errors.As(err, &consentErr):
				tools = nil
			default:
				return nil, err
			}
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
		if g.connections != nil && connectionToolPermitted(rc) {
			tools = appendGatewayTools(tools, g.connections.Definitions(ctx, rc))
		}
		if g.store != nil && isStore {
			tools = appendGatewayTools(tools, g.store.Definitions(ctx, rc))
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
			return g.store.Call(ctx, rc, baseURL, p.Name, p.Arguments)
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
