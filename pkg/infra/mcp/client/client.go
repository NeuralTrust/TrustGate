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

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	clientName    = "trustgate"
	clientVersion = "1.0"

	responseHeaderTimeout = 30 * time.Second
)

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
	cs, attempt, err := c.connect(ctx, target, false)
	if err == nil {
		return &Session{cs: cs, url: target.URL}, nil
	}
	if ctx.Err() != nil ||
		!attempt.discoverLegacyCandidate.Load() ||
		!attempt.initializeBadRequest.Load() {
		return nil, wrapUnreachable(target.URL, err)
	}

	cs, _, legacyErr := c.connect(ctx, target, true)
	if legacyErr != nil {
		return nil, wrapUnreachable(target.URL, fmt.Errorf("legacy handshake fallback: %w", legacyErr))
	}
	return &Session{cs: cs, url: target.URL}, nil
}

func (c *Client) connect(
	ctx context.Context,
	target appmcp.Target,
	legacyFallback bool,
) (*sdk.ClientSession, *handshakeRoundTripper, error) {
	attempt := &handshakeRoundTripper{
		headers:        target.Headers,
		transport:      upstreamTransport,
		legacyFallback: legacyFallback,
	}
	transport := &sdk.StreamableClientTransport{
		Endpoint: target.URL,
		HTTPClient: &http.Client{
			Transport:     attempt,
			CheckRedirect: rejectRedirect,
		},
		DisableStandaloneSSE: true,
	}
	cli := sdk.NewClient(
		&sdk.Implementation{Name: clientName, Version: clientVersion},
		&sdk.ClientOptions{},
	)
	cs, err := cli.Connect(ctx, transport, nil)
	if err != nil {
		if attempt.unauthorizedResponses.Load() > 0 {
			err = fmt.Errorf("%w: %v", appmcp.ErrUpstreamUnauthorized, err)
		}
		return nil, attempt, err
	}
	return cs, attempt, nil
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
	ctx, unauthorized := trackUnauthorized(ctx)
	var items []*sdk.Tool
	for t, err := range s.cs.Tools(ctx, nil) {
		if err != nil {
			return nil, fmt.Errorf("mcp client: tools/list: %w", mapSessionError(err, unauthorized))
		}
		items = append(items, t)
	}
	return mapItems[appmcp.Tool]("tools/list", items)
}

func (s *Session) CallTool(ctx context.Context, name string, arguments json.RawMessage) (json.RawMessage, error) {
	ctx, unauthorized := trackUnauthorized(ctx)
	params := &sdk.CallToolParams{Name: name}
	if len(arguments) > 0 {
		params.Arguments = arguments
	}
	res, err := s.cs.CallTool(ctx, params)
	if err != nil {
		return nil, mapSessionError(err, unauthorized)
	}
	return marshalResult("tools/call", res)
}

func (s *Session) ListResources(ctx context.Context) ([]appmcp.Resource, error) {
	if !s.SupportsResources() {
		return nil, nil
	}
	ctx, unauthorized := trackUnauthorized(ctx)
	var items []*sdk.Resource
	for r, err := range s.cs.Resources(ctx, nil) {
		if err != nil {
			return nil, fmt.Errorf("mcp client: resources/list: %w", mapSessionError(err, unauthorized))
		}
		items = append(items, r)
	}
	return mapItems[appmcp.Resource]("resources/list", items)
}

func (s *Session) ListResourceTemplates(ctx context.Context) ([]appmcp.ResourceTemplate, error) {
	if !s.SupportsResources() {
		return nil, nil
	}
	ctx, unauthorized := trackUnauthorized(ctx)
	var items []*sdk.ResourceTemplate
	for t, err := range s.cs.ResourceTemplates(ctx, nil) {
		if err != nil {
			return nil, fmt.Errorf("mcp client: resources/templates/list: %w", mapSessionError(err, unauthorized))
		}
		items = append(items, t)
	}
	return mapItems[appmcp.ResourceTemplate]("resources/templates/list", items)
}

func (s *Session) ReadResource(ctx context.Context, uri string) (json.RawMessage, error) {
	if !s.SupportsResources() {
		return nil, fmt.Errorf("%w: resources/read: %s", appmcp.ErrNotSupported, s.url)
	}
	ctx, unauthorized := trackUnauthorized(ctx)
	res, err := s.cs.ReadResource(ctx, &sdk.ReadResourceParams{URI: uri})
	if err != nil {
		return nil, mapSessionError(err, unauthorized)
	}
	return marshalResult("resources/read", res)
}

func (s *Session) ListPrompts(ctx context.Context) ([]appmcp.Prompt, error) {
	if !s.SupportsPrompts() {
		return nil, nil
	}
	ctx, unauthorized := trackUnauthorized(ctx)
	var items []*sdk.Prompt
	for p, err := range s.cs.Prompts(ctx, nil) {
		if err != nil {
			return nil, fmt.Errorf("mcp client: prompts/list: %w", mapSessionError(err, unauthorized))
		}
		items = append(items, p)
	}
	return mapItems[appmcp.Prompt]("prompts/list", items)
}

func (s *Session) GetPrompt(ctx context.Context, name string, arguments map[string]string) (json.RawMessage, error) {
	if !s.SupportsPrompts() {
		return nil, fmt.Errorf("%w: prompts/get: %s", appmcp.ErrNotSupported, s.url)
	}
	ctx, unauthorized := trackUnauthorized(ctx)
	res, err := s.cs.GetPrompt(ctx, &sdk.GetPromptParams{Name: name, Arguments: arguments})
	if err != nil {
		return nil, mapSessionError(err, unauthorized)
	}
	return marshalResult("prompts/get", res)
}

func (s *Session) Ping(ctx context.Context) error {
	ctx, unauthorized := trackUnauthorized(ctx)
	return mapSessionError(s.cs.Ping(ctx, nil), unauthorized)
}

type unauthorizedTrackerKey struct{}

func trackUnauthorized(ctx context.Context) (context.Context, *atomic.Bool) {
	tracker := &atomic.Bool{}
	return context.WithValue(ctx, unauthorizedTrackerKey{}, tracker), tracker
}

func mapSessionError(err error, unauthorized *atomic.Bool) error {
	if err != nil && unauthorized.Load() {
		return fmt.Errorf("%w: %v", appmcp.ErrUpstreamUnauthorized, err)
	}
	return mapRPCError(err)
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
