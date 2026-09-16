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

package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/gofiber/fiber/v2"
)

const HeaderGatewaySlug = "X-AG-Gateway-Slug"

type GatewayResolver interface {
	Resolve(c *fiber.Ctx) (*gatewaydomain.Gateway, error)
}

// WithResolvedGateway best-effort resolves the gateway addressed by the request
// (gateway-slug header first, then subdomain host) and returns a context carrying
// it. On any resolution miss it returns the request context unchanged, so callers
// that can still operate without a pinned gateway keep working.
func WithResolvedGateway(c *fiber.Ctx, r GatewayResolver) context.Context {
	ctx := c.UserContext()
	if r == nil {
		return ctx
	}
	gw, err := r.Resolve(c)
	if err != nil {
		return ctx
	}
	return appgateway.WithGateway(ctx, gw)
}

// NewGatewayResolver builds the resolver that identifies the gateway addressed by
// a request. The X-AG-Gateway-Slug header always takes precedence; when it is
// absent the resolver falls back to the {slug}.{baseDomain} subdomain host, and it
// only fails when neither identifies a gateway.
//
// alsoAccept lists further suffixes the same deployment answers on. baseDomain
// stays the one the gateway publishes in its URLs; the extras only widen what
// the resolver recognises.
func NewGatewayResolver(finder appgateway.Finder, baseDomain string, alsoAccept ...string) GatewayResolver {
	return &HeaderGatewayResolver{
		finder:       finder,
		hostFallback: NewSubdomainGatewayResolver(finder, baseDomain, alsoAccept...),
	}
}

type SubdomainGatewayResolver struct {
	finder appgateway.Finder
	// Every suffix this deployment answers on, canonical first. A gateway is
	// often published under more than one: a second domain put in front of the
	// same cluster to make it reachable from outside, for instance. Recognising
	// only the canonical one does not merely fail to route — the OAuth authorize
	// path treats a missing gateway as "none addressed" and mints a session
	// stamped with the zero gateway id, which the MCP plane then refuses with an
	// opaque 401 the client retries forever.
	baseDomains []string
}

func NewSubdomainGatewayResolver(finder appgateway.Finder, baseDomain string, alsoAccept ...string) GatewayResolver {
	domains := make([]string, 0, 1+len(alsoAccept))
	for _, d := range append([]string{baseDomain}, alsoAccept...) {
		if d = strings.Trim(strings.ToLower(strings.TrimSpace(d)), "."); d != "" {
			domains = append(domains, d)
		}
	}
	return &SubdomainGatewayResolver{finder: finder, baseDomains: domains}
}

func (r *SubdomainGatewayResolver) Resolve(c *fiber.Ctx) (*gatewaydomain.Gateway, error) {
	slug, err := parseGatewaySlugFromHosts(string(c.Request().Host()), r.baseDomains)
	if err != nil {
		return nil, err
	}
	return resolveGatewayBySlug(c, r.finder, slug)
}

type HeaderGatewayResolver struct {
	finder       appgateway.Finder
	hostFallback GatewayResolver
}

func (r *HeaderGatewayResolver) Resolve(c *fiber.Ctx) (*gatewaydomain.Gateway, error) {
	raw := strings.TrimSpace(c.Get(HeaderGatewaySlug))
	if raw == "" {
		return r.hostFallback.Resolve(c)
	}
	slug := gatewaydomain.NormalizeSlug(raw)
	if !gatewaydomain.IsValidSlug(slug) {
		return nil, fmt.Errorf(
			"%w: header %s contains an invalid gateway slug",
			appauth.ErrInvalidAuthRequest, HeaderGatewaySlug,
		)
	}
	return resolveGatewayBySlug(c, r.finder, slug)
}

func resolveGatewayBySlug(c *fiber.Ctx, finder appgateway.Finder, slug string) (*gatewaydomain.Gateway, error) {
	gw, err := finder.FindBySlug(c.UserContext(), slug)
	if err != nil {
		if errors.Is(err, commonerrors.ErrNotFound) {
			return nil, fmt.Errorf("%w: gateway %q is unknown", appauth.ErrInvalidAuthRequest, slug)
		}
		return nil, fmt.Errorf("resolve gateway by slug: %w", err)
	}
	return gw, nil
}

// parseGatewaySlugFromHosts takes the slug under the first suffix the host
// matches. The error names only the canonical domain: the extras exist so an
// operator can reach a deployment by another route, and an operator reading
// this error wants to be told the address the gateway publishes.
func parseGatewaySlugFromHosts(rawHost string, baseDomains []string) (string, error) {
	if len(baseDomains) == 0 {
		return "", fmt.Errorf("%w: no MCP base domain is configured", appauth.ErrInvalidAuthRequest)
	}
	var firstErr error
	for _, d := range baseDomains {
		slug, err := parseGatewaySlugFromHost(rawHost, d)
		if err == nil {
			return slug, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return "", firstErr
}

func parseGatewaySlugFromHost(rawHost, baseDomain string) (string, error) {
	host, err := normalizeHost(rawHost)
	if err != nil {
		return "", err
	}
	baseDomain = strings.Trim(strings.ToLower(strings.TrimSpace(baseDomain)), ".")
	suffix := "." + baseDomain
	if !strings.HasSuffix(host, suffix) {
		return "", fmt.Errorf("%w: host must match {slug}.%s", appauth.ErrInvalidAuthRequest, baseDomain)
	}
	slug := strings.TrimSuffix(host, suffix)
	if slug == "" || strings.Contains(slug, ".") {
		return "", fmt.Errorf("%w: host must contain exactly one gateway slug label", appauth.ErrInvalidAuthRequest)
	}
	slug = gatewaydomain.NormalizeSlug(slug)
	if !gatewaydomain.IsValidSlug(slug) {
		return "", fmt.Errorf("%w: host contains an invalid gateway slug", appauth.ErrInvalidAuthRequest)
	}
	return slug, nil
}

func normalizeHost(rawHost string) (string, error) {
	rawHost = strings.TrimSpace(rawHost)
	if rawHost == "" {
		return "", fmt.Errorf("%w: host is required", appauth.ErrInvalidAuthRequest)
	}
	host := rawHost
	if strings.Contains(rawHost, ":") {
		if strings.Count(rawHost, ":") != 1 {
			return "", fmt.Errorf("%w: host is malformed", appauth.ErrInvalidAuthRequest)
		}
		withoutPort, port, err := net.SplitHostPort(rawHost)
		if err != nil {
			return "", fmt.Errorf("%w: host port is malformed", appauth.ErrInvalidAuthRequest)
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return "", fmt.Errorf("%w: host port is malformed", appauth.ErrInvalidAuthRequest)
		}
		host = withoutPort
	}
	host = strings.Trim(strings.ToLower(host), ".")
	if host == "" {
		return "", fmt.Errorf("%w: host is required", appauth.ErrInvalidAuthRequest)
	}
	return host, nil
}
