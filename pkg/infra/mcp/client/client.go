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
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
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

// legacyProtocolVersions are offered, newest first, when an upstream rejects
// the initialize handshake with HTTP 400. The SDK only ever offers 2025-11-25
// on its own legacy path, so that revision is already covered by the first
// attempt and is absent here.
var legacyProtocolVersions = []string{
	"2025-06-18",
	"2025-03-26",
	"2024-11-05",
}

// upstreamTransport dials any address: a fixed registry URL was configured by
// an admin and is trusted as much as any other admin-set upstream.
var upstreamTransport = newUpstreamTransport(nil)

// restrictedUpstreamTransport serves targets whose URL came out of per-user
// variable substitution (Target.RestrictPrivateNetwork). Its dialer resolves the
// host itself and refuses every non-public address, then connects to the very
// address it checked — so neither an IP literal that slipped past validation
// nor a hostname that rebinds to 10.0.0.5 between check and dial can reach the
// gateway's network.
var restrictedUpstreamTransport = newUpstreamTransport(dialPublicOnly)

func newUpstreamTransport(dial func(context.Context, string, string) (net.Conn, error)) http.RoundTripper {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return http.DefaultTransport
	}
	cloned := t.Clone()
	cloned.ResponseHeaderTimeout = responseHeaderTimeout
	if dial != nil {
		cloned.DialContext = dial
	}
	return cloned
}

func transportFor(target appmcp.Target) http.RoundTripper {
	if target.RestrictPrivateNetwork {
		return restrictedUpstreamTransport
	}
	return upstreamTransport
}

// errPrivateUpstreamAddress is the dial-time refusal for a restricted target.
// It names the host but never the resolved address, which would map the
// gateway's own network for the caller.
var errPrivateUpstreamAddress = errors.New("upstream host resolves to a private, loopback, link-local or otherwise non-public address")

// publicDialer mirrors http.DefaultTransport's dialer settings.
var publicDialer = &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}

// dialPublicOnly is the DialContext of restrictedUpstreamTransport. Every
// address the host resolves to must be public unicast — one private answer in a
// mixed set refuses the whole dial, since an attacker controls the answer set —
// and the connection is made to a checked address, never to the name again.
func dialPublicOnly(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := resolveHost(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if !isPublicUnicast(ip) {
			return nil, fmt.Errorf("%w: %s", errPrivateUpstreamAddress, host)
		}
	}
	var lastErr error
	for _, ip := range ips {
		conn, dialErr := publicDialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

func resolveHost(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses found for %s", host)
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// Address ranges the standard library does not classify but that never denote a
// public upstream: carrier-grade NAT, "this" network, IETF protocol assignments,
// the reserved class-E block (which includes the broadcast address), NAT64 and
// the IPv6 discard prefix.
var (
	cgnatV4    = mustCIDR("100.64.0.0/10")
	thisNetV4  = mustCIDR("0.0.0.0/8")
	ietfV4     = mustCIDR("192.0.0.0/24")
	reservedV4 = mustCIDR("240.0.0.0/4")
	nat64V6    = mustCIDR("64:ff9b::/96")
	discardV6  = mustCIDR("100::/64")
)

func mustCIDR(cidr string) *net.IPNet {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return n
}

// isPublicUnicast reports whether ip is an address a per-user upstream may
// legitimately live at: globally routable unicast, nothing else.
func isPublicUnicast(ip net.IP) bool {
	if ip == nil ||
		ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		for _, blocked := range []*net.IPNet{cgnatV4, thisNetV4, ietfV4, reservedV4} {
			if blocked.Contains(ip4) {
				return false
			}
		}
		return true
	}
	if len(ip) == net.IPv6len && nat64V6.Contains(ip) {
		// NAT64 embeds the IPv4 target in the low 32 bits; judge that.
		return isPublicUnicast(net.IP(ip[12:16]))
	}
	return !discardV6.Contains(ip)
}

type Client struct{}

func New() *Client { return &Client{} }

type Session struct {
	cs     *sdk.ClientSession
	url    string
	mu     sync.RWMutex
	closed bool
}

var errSessionClosed = errors.New("mcp client session is closed")

var _ appmcp.Upstream = (*Session)(nil)

func (c *Client) Connect(ctx context.Context, target appmcp.Target) (*Session, error) {
	cs, attempt, err := c.connect(ctx, target, false, "")
	if err == nil {
		return &Session{cs: cs, url: redactURL(target.URL)}, nil
	}
	if ctx.Err() != nil ||
		!attempt.discoverLegacyCandidate.Load() ||
		!attempt.initializeBadRequest.Load() {
		return nil, wrapUnreachable(target.URL, err)
	}

	legacyErr := err
	for _, protocolVersion := range legacyProtocolVersions {
		cs, attempt, err = c.connect(ctx, target, true, protocolVersion)
		if err == nil {
			return &Session{cs: cs, url: redactURL(target.URL)}, nil
		}
		legacyErr = fmt.Errorf("legacy handshake fallback (protocolVersion %s): %w", protocolVersion, err)
		if ctx.Err() != nil || !attempt.initializeBadRequest.Load() {
			break
		}
	}
	return nil, wrapUnreachable(target.URL, legacyErr)
}

func (c *Client) connect(
	ctx context.Context,
	target appmcp.Target,
	legacyFallback bool,
	protocolVersion string,
) (*sdk.ClientSession, *handshakeRoundTripper, error) {
	attempt := &handshakeRoundTripper{
		headers:         target.Headers,
		transport:       transportFor(target),
		legacyFallback:  legacyFallback,
		protocolVersion: protocolVersion,
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
			err = fmt.Errorf("%w: %w", appmcp.ErrUpstreamUnauthorized, err)
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

func (s *Session) SupportsResources() bool {
	if err := s.lock(); err != nil {
		return false
	}
	defer s.mu.RUnlock()
	return s.capabilities().Resources != nil
}

func (s *Session) SupportsPrompts() bool {
	if err := s.lock(); err != nil {
		return false
	}
	defer s.mu.RUnlock()
	return s.capabilities().Prompts != nil
}

func (s *Session) ListTools(ctx context.Context) ([]appmcp.Tool, error) {
	if err := s.lock(); err != nil {
		return nil, err
	}
	defer s.mu.RUnlock()
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
	if err := s.lock(); err != nil {
		return nil, err
	}
	defer s.mu.RUnlock()
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
	if err := s.lock(); err != nil {
		return nil, err
	}
	defer s.mu.RUnlock()
	if s.capabilities().Resources == nil {
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
	if err := s.lock(); err != nil {
		return nil, err
	}
	defer s.mu.RUnlock()
	if s.capabilities().Resources == nil {
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
	if err := s.lock(); err != nil {
		return nil, err
	}
	defer s.mu.RUnlock()
	if s.capabilities().Resources == nil {
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
	if err := s.lock(); err != nil {
		return nil, err
	}
	defer s.mu.RUnlock()
	if s.capabilities().Prompts == nil {
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
	if err := s.lock(); err != nil {
		return nil, err
	}
	defer s.mu.RUnlock()
	if s.capabilities().Prompts == nil {
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
	if err := s.lock(); err != nil {
		return err
	}
	defer s.mu.RUnlock()
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
		return fmt.Errorf("%w: %w", appmcp.ErrUpstreamUnauthorized, err)
	}
	return mapRPCError(err)
}

func (s *Session) lock() error {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return errSessionClosed
	}
	return nil
}

func (s *Session) Close(context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	_ = s.cs.Close()
}

func marshalResult(method string, res any) (json.RawMessage, error) {
	raw, err := json.Marshal(res)
	if err != nil {
		return nil, fmt.Errorf("mcp client: %s: encode result: %w", method, err)
	}
	return raw, nil
}
