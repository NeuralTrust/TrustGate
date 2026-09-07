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
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
)

var ErrMethodNotFound = errors.New("mcp: method not found")

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

func (d *RPCDispatcher) WithStoreScoper(scoper appstore.Scoper) *RPCDispatcher {
	d.storeScoper = scoper
	return d
}

// StoreScoper returns the Store scoper this dispatcher applies before every
// method (nil when the Store is not wired), so the stream's surface watcher can
// fingerprint the same view the caller's tools/list gets.
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

func (d *RPCDispatcher) listTools(ctx context.Context, req dispatchRequest) (any, error) {
	if err := d.checkRateLimit(ctx, req.consumer); err != nil {
		return nil, err
	}
	isStore := req.consumer != nil && req.consumer.Consumer != nil && consumerdomain.IsStoreConsumer(req.consumer.Consumer)
	tools, err := d.composer.ListTools(ctx, req.consumer)
	if err != nil {
		var consentErr *ConsentRequiredError
		switch {
		case isStore && errors.Is(err, ErrNoMCPRegistries):
			tools = nil
		case isStore && errors.Is(err, ErrUpstreamUnavailable):
			tools = nil
		case errors.As(err, &consentErr):
			tools = nil
		default:
			return nil, err
		}
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
	if d.connections != nil && connectionToolPermitted(req.consumer) {
		tools = appendGatewayTools(tools, d.connections.Definitions(ctx, req.consumer))
	}
	if d.store != nil && isStore {
		tools = appendGatewayTools(tools, d.store.Definitions(ctx, req.consumer))
	}
	result["tools"] = tools
	return result, nil
}

func (d *RPCDispatcher) callTool(ctx context.Context, req dispatchRequest) (any, error) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments,omitempty"`
	}
	if err := json.Unmarshal(req.params, &params); err != nil || params.Name == "" {
		return nil, &InvalidParamsError{Reason: "tools/call requires params.name"}
	}
	if err := d.checkRateLimit(ctx, req.consumer); err != nil {
		return nil, err
	}
	if d.connections != nil && d.connections.Handles(params.Name) {
		if !connectionToolPermitted(req.consumer) {
			return nil, &ToolNotPermittedError{Tool: params.Name}
		}
		return d.connections.Call(ctx, req.consumer, req.baseURL, params.Name)
	}
	if d.store != nil && d.store.Handles(params.Name) {
		if req.consumer == nil || !consumerdomain.IsStoreConsumer(req.consumer.Consumer) {
			return nil, &ToolNotPermittedError{Tool: params.Name}
		}
		return d.store.Call(ctx, req.consumer, req.baseURL, params.Name, params.Arguments)
	}
	pre, err := d.plugins.PreRequest(ctx, req.consumer, params.Name, params.Arguments)
	if err != nil {
		return nil, err
	}
	arguments := params.Arguments
	if pre != nil {
		if pre.Result != nil {
			return pre.Result, nil
		}
		if pre.Arguments != nil {
			arguments = pre.Arguments
		}
	}
	result, err := d.composer.CallTool(ctx, req.consumer, params.Name, arguments)
	if err != nil {
		return nil, err
	}
	post, err := d.plugins.PreResponse(ctx, req.consumer, params.Name, arguments, result)
	if err != nil {
		return nil, err
	}
	if post != nil && post.Result != nil {
		result = post.Result
	}
	return result, nil
}

func (d *RPCDispatcher) listResources(ctx context.Context, req dispatchRequest) (any, error) {
	if err := d.checkRateLimit(ctx, req.consumer); err != nil {
		return nil, err
	}
	resources, err := d.composer.ListResources(ctx, req.consumer)
	if err != nil {
		return nil, err
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
		return nil, err
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
		return nil, err
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

func connectionToolPermitted(consumer *appconsumer.RoutableConsumer) bool {
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
