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
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

var ErrMethodNotFound = errors.New("mcp: method not found")

type InvalidParamsError struct {
	Reason string
}

func (e *InvalidParamsError) Error() string { return "mcp: invalid params: " + e.Reason }

type RPCGateway struct {
	composer appmcp.Composer
	plugins  *appmcp.PluginRunner
	limiter  ratelimitapp.Checker
}

// NewRPCGateway wires MCP dispatch; nil limiter defaults to noop.
func NewRPCGateway(composer appmcp.Composer, plugins *appmcp.PluginRunner, limiter ratelimitapp.Checker) *RPCGateway {
	if limiter == nil {
		limiter = ratelimitapp.NewNoopChecker()
	}
	return &RPCGateway{composer: composer, plugins: plugins, limiter: limiter}
}

func (g *RPCGateway) Dispatch(ctx context.Context, rc *appconsumer.RoutableConsumer, method string, params json.RawMessage) (any, error) {
	span, ctx := g.startSpan(ctx, method, params)
	result, err := g.dispatch(ctx, rc, method, params)
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
		span.SetMCPStatus("ok", 0)
		return
	}
	span.SetError(err.Error())
	var rpcErr *appmcp.RPCError
	switch {
	case errors.As(err, &rpcErr):
		span.SetMCPStatus("error", int(rpcErr.Code))
	case errors.Is(err, appmcp.ErrToolNotFound), errors.Is(err, appmcp.ErrPromptNotFound),
		errors.Is(err, appmcp.ErrResourceNotFound):
		span.SetMCPStatus("not_found", 0)
	default:
		span.SetMCPStatus("error", 0)
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
		if tools == nil {
			tools = []appmcp.Tool{}
		}
		return map[string]any{"tools": tools}, nil
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
		if err := g.plugins.PreRequest(ctx, rc, p.Name, p.Arguments); err != nil {
			return nil, err
		}
		result, err := g.composer.CallTool(ctx, rc, p.Name, p.Arguments)
		if err != nil {
			return nil, err
		}
		if err := g.plugins.PreResponse(ctx, rc, p.Name, p.Arguments, result); err != nil {
			return nil, err
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
