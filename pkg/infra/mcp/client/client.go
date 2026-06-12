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
	clientName    = "agentgateway"
	clientVersion = "1.0"

	responseHeaderTimeout = 30 * time.Second
)

// upstreamTransport bounds connection setup and time-to-first-byte without
// capping the whole exchange: long-running tools/call invocations are limited
// only by the caller's context, not by a global http.Client timeout.
var upstreamTransport = func() http.RoundTripper {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return http.DefaultTransport
	}
	cloned := t.Clone()
	cloned.ResponseHeaderTimeout = responseHeaderTimeout
	return cloned
}()

type Client struct{}

func New() *Client { return &Client{} }

type Session struct {
	cs  *sdk.ClientSession
	url string
}

var _ appmcp.Upstream = (*Session)(nil)

func (c *Client) Connect(ctx context.Context, target appmcp.Target) (*Session, error) {
	transport := &sdk.StreamableClientTransport{
		Endpoint: target.URL,
		HTTPClient: &http.Client{
			Transport: &headerRoundTripper{headers: target.Headers},
		},
		DisableStandaloneSSE: true,
	}
	cli := sdk.NewClient(
		&sdk.Implementation{Name: clientName, Version: clientVersion},
		&sdk.ClientOptions{},
	)
	cs, err := cli.Connect(ctx, transport, nil)
	if err != nil {
		return nil, wrapUnreachable(target.URL, err)
	}
	return &Session{cs: cs, url: target.URL}, nil
}

type headerRoundTripper struct {
	headers map[string]string
}

func (t *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	return upstreamTransport.RoundTrip(req)
}

func (s *Session) capabilities() *sdk.ServerCapabilities {
	if res := s.cs.InitializeResult(); res != nil && res.Capabilities != nil {
		return res.Capabilities
	}
	return &sdk.ServerCapabilities{}
}

func (s *Session) SupportsResources() bool { return s.capabilities().Resources != nil }

func (s *Session) SupportsPrompts() bool { return s.capabilities().Prompts != nil }

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

func (s *Session) Ping(ctx context.Context) error {
	return s.cs.Ping(ctx, nil)
}

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
