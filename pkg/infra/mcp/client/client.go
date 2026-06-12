package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	appmcp "github.com/NeuralTrust/AgentGateway/pkg/app/mcp"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	clientName     = "agentgateway"
	clientVersion  = "1.0"
	defaultTimeout = 30 * time.Second
)

// Client dials upstream MCP servers via the official SDK's Streamable HTTP
// transport.
type Client struct{}

func New() *Client { return &Client{} }

// Session is an initialized MCP connection to one upstream server.
type Session struct {
	cs  *sdk.ClientSession
	url string
}

var _ appmcp.Upstream = (*Session)(nil)

// Connect performs the initialize handshake (the SDK negotiates the protocol
// version and sends notifications/initialized).
func (c *Client) Connect(ctx context.Context, target appmcp.Target) (*Session, error) {
	transport := &sdk.StreamableClientTransport{
		Endpoint: target.URL,
		HTTPClient: &http.Client{
			Timeout:   defaultTimeout,
			Transport: &headerRoundTripper{headers: target.Headers},
		},
		// The gateway is a request/response proxy: it has nowhere to relay
		// server-initiated messages, so it skips the standalone SSE stream.
		DisableStandaloneSSE: true,
	}
	cli := sdk.NewClient(
		&sdk.Implementation{Name: clientName, Version: clientVersion},
		// No elicitation or sampling handlers on purpose; see package doc.
		&sdk.ClientOptions{},
	)
	cs, err := cli.Connect(ctx, transport, nil)
	if err != nil {
		return nil, wrapUnreachable(target.URL, err)
	}
	return &Session{cs: cs, url: target.URL}, nil
}

// headerRoundTripper injects the target's static headers (downstream
// credentials resolved by the gateway) into every upstream request.
type headerRoundTripper struct {
	headers map[string]string
}

func (t *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	return http.DefaultTransport.RoundTrip(req)
}

// capabilities returns the upstream's advertised capabilities (never nil).
func (s *Session) capabilities() *sdk.ServerCapabilities {
	if res := s.cs.InitializeResult(); res != nil && res.Capabilities != nil {
		return res.Capabilities
	}
	return &sdk.ServerCapabilities{}
}

// SupportsResources reports whether the upstream advertises the resources
// capability.
func (s *Session) SupportsResources() bool { return s.capabilities().Resources != nil }

// SupportsPrompts reports whether the upstream advertises the prompts
// capability.
func (s *Session) SupportsPrompts() bool { return s.capabilities().Prompts != nil }

// ListTools fetches all tools, following pagination cursors.
func (s *Session) ListTools(ctx context.Context) ([]appmcp.Tool, error) {
	var items []*sdk.Tool
	for t, err := range s.cs.Tools(ctx, nil) {
		if err != nil {
			return nil, fmt.Errorf("mcp client: tools/list: %w", mapRPCError(err))
		}
		items = append(items, t)
	}
	return mapItems[appmcp.Tool]("tools/list", items)
}

// CallTool invokes a tool and returns the raw CallToolResult, which the
// gateway forwards to its own client verbatim.
func (s *Session) CallTool(ctx context.Context, name string, arguments json.RawMessage) (json.RawMessage, error) {
	params := &sdk.CallToolParams{Name: name}
	if len(arguments) > 0 {
		params.Arguments = arguments
	}
	res, err := s.cs.CallTool(ctx, params)
	if err != nil {
		return nil, mapRPCError(err)
	}
	return marshalResult("tools/call", res)
}

// ListResources fetches all resources, following pagination cursors. Servers
// without the resources capability yield an empty list.
func (s *Session) ListResources(ctx context.Context) ([]appmcp.Resource, error) {
	if !s.SupportsResources() {
		return nil, nil
	}
	var items []*sdk.Resource
	for r, err := range s.cs.Resources(ctx, nil) {
		if err != nil {
			return nil, fmt.Errorf("mcp client: resources/list: %w", mapRPCError(err))
		}
		items = append(items, r)
	}
	return mapItems[appmcp.Resource]("resources/list", items)
}

// ListResourceTemplates fetches all resource templates, following pagination
// cursors. Servers without the resources capability yield an empty list.
func (s *Session) ListResourceTemplates(ctx context.Context) ([]appmcp.ResourceTemplate, error) {
	if !s.SupportsResources() {
		return nil, nil
	}
	var items []*sdk.ResourceTemplate
	for t, err := range s.cs.ResourceTemplates(ctx, nil) {
		if err != nil {
			return nil, fmt.Errorf("mcp client: resources/templates/list: %w", mapRPCError(err))
		}
		items = append(items, t)
	}
	return mapItems[appmcp.ResourceTemplate]("resources/templates/list", items)
}

// ReadResource reads one resource by URI and returns the raw result.
func (s *Session) ReadResource(ctx context.Context, uri string) (json.RawMessage, error) {
	if !s.SupportsResources() {
		return nil, fmt.Errorf("%w: resources/read: %s", appmcp.ErrNotSupported, s.url)
	}
	res, err := s.cs.ReadResource(ctx, &sdk.ReadResourceParams{URI: uri})
	if err != nil {
		return nil, mapRPCError(err)
	}
	return marshalResult("resources/read", res)
}

// ListPrompts fetches all prompts, following pagination cursors. Servers
// without the prompts capability yield an empty list.
func (s *Session) ListPrompts(ctx context.Context) ([]appmcp.Prompt, error) {
	if !s.SupportsPrompts() {
		return nil, nil
	}
	var items []*sdk.Prompt
	for p, err := range s.cs.Prompts(ctx, nil) {
		if err != nil {
			return nil, fmt.Errorf("mcp client: prompts/list: %w", mapRPCError(err))
		}
		items = append(items, p)
	}
	return mapItems[appmcp.Prompt]("prompts/list", items)
}

// GetPrompt renders one prompt and returns the raw result.
func (s *Session) GetPrompt(ctx context.Context, name string, arguments map[string]string) (json.RawMessage, error) {
	if !s.SupportsPrompts() {
		return nil, fmt.Errorf("%w: prompts/get: %s", appmcp.ErrNotSupported, s.url)
	}
	res, err := s.cs.GetPrompt(ctx, &sdk.GetPromptParams{Name: name, Arguments: arguments})
	if err != nil {
		return nil, mapRPCError(err)
	}
	return marshalResult("prompts/get", res)
}

// Ping checks upstream liveness.
func (s *Session) Ping(ctx context.Context) error {
	return s.cs.Ping(ctx, nil)
}

// Close terminates the upstream session (best effort).
func (s *Session) Close(context.Context) {
	_ = s.cs.Close()
}

func marshalResult(method string, res any) (json.RawMessage, error) {
	raw, err := json.Marshal(res)
	if err != nil {
		return nil, fmt.Errorf("mcp client: %s: encode result: %w", method, err)
	}
	return raw, nil
}
