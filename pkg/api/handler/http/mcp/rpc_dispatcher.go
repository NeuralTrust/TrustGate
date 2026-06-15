package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/AgentGateway/pkg/app/mcp"
)

var ErrMethodNotFound = errors.New("mcp: method not found")

type InvalidParamsError struct {
	Reason string
}

func (e *InvalidParamsError) Error() string { return "mcp: invalid params: " + e.Reason }

type RPCGateway struct {
	composer appmcp.Composer
}

func NewRPCGateway(composer appmcp.Composer) *RPCGateway {
	return &RPCGateway{composer: composer}
}

func (g *RPCGateway) Dispatch(ctx context.Context, rc *appconsumer.RoutableConsumer, method string, params json.RawMessage) (any, error) {
	switch method {
	case "tools/list":
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
		return g.composer.CallTool(ctx, rc, p.Name, p.Arguments)
	case "resources/list":
		resources, err := g.composer.ListResources(ctx, rc)
		if err != nil {
			return nil, err
		}
		if resources == nil {
			resources = []appmcp.Resource{}
		}
		return map[string]any{"resources": resources}, nil
	case "resources/templates/list":
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
		return g.composer.ReadResource(ctx, rc, p.URI)
	case "prompts/list":
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
		return g.composer.GetPrompt(ctx, rc, p.Name, p.Arguments)
	default:
		return nil, fmt.Errorf("%w: %s", ErrMethodNotFound, method)
	}
}
