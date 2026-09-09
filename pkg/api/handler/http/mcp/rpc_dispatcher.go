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
	"net/http"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

var ErrMethodNotFound = appmcp.ErrMethodNotFound

type InvalidParamsError = appmcp.InvalidParamsError

type RPCGateway struct {
	dispatcher *appmcp.RPCDispatcher
}

func NewRPCGateway(composer appmcp.Composer, plugins *appmcp.PluginRunner, limiter ratelimitapp.Checker) *RPCGateway {
	return &RPCGateway{dispatcher: appmcp.NewRPCDispatcher(composer, plugins, limiter, nil, nil)}
}

func NewRPCGatewayWithConnections(
	composer appmcp.Composer,
	plugins *appmcp.PluginRunner,
	limiter ratelimitapp.Checker,
	connections appmcp.ConnectionTool,
) *RPCGateway {
	return &RPCGateway{dispatcher: appmcp.NewRPCDispatcher(composer, plugins, limiter, connections, nil)}
}

func NewRPCGatewayWithMetaTools(
	composer appmcp.Composer,
	plugins *appmcp.PluginRunner,
	limiter ratelimitapp.Checker,
	connections appmcp.ConnectionTool,
	store appmcp.StoreTool,
) *RPCGateway {
	return &RPCGateway{dispatcher: appmcp.NewRPCDispatcher(composer, plugins, limiter, connections, store)}
}

// WithInventoryTool wires the meta-tool that lists every tool the caller has,
// server by server (see appmcp.InventoryTool).
func (g *RPCGateway) WithInventoryTool(inventory appmcp.InventoryTool) *RPCGateway {
	g.dispatcher.WithInventoryTool(inventory)
	return g
}

func (g *RPCGateway) WithStoreScoper(scoper appstore.Scoper) *RPCGateway {
	g.dispatcher.WithStoreScoper(scoper)
	return g
}

// StoreScoper exposes the dispatcher's Store scoper (nil when not wired).
func (g *RPCGateway) StoreScoper() appstore.Scoper {
	if g == nil || g.dispatcher == nil {
		return nil
	}
	return g.dispatcher.StoreScoper()
}

func (g *RPCGateway) Dispatch(ctx context.Context, consumer *appconsumer.RoutableConsumer, method string, params json.RawMessage) (any, error) {
	return g.DispatchWithBaseURL(ctx, consumer, "", method, params)
}

func (g *RPCGateway) DispatchWithBaseURL(
	ctx context.Context,
	consumer *appconsumer.RoutableConsumer,
	baseURL,
	method string,
	params json.RawMessage,
) (any, error) {
	span, ctx := g.startSpan(ctx, method, params)
	result, err := g.dispatcher.Dispatch(ctx, consumer, baseURL, method, params)
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

func mcpRequestAttrs(method string, params json.RawMessage) (operation, tool, prompt, resourceURI string) {
	switch method {
	case "server/discover", "tools/list", "resources/list", "resources/templates/list", "prompts/list":
		return "discovery", "", "", ""
	case "tools/call":
		var p struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(params, &p)
		return "tool", p.Name, "", ""
	case "resources/read":
		var p struct {
			URI string `json:"uri"`
		}
		_ = json.Unmarshal(params, &p)
		return "resource", "", "", p.URI
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
