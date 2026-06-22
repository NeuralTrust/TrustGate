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

const gatewayDiscoveryModeSubdomain = "subdomain"

type GatewayResolver interface {
	Resolve(c *fiber.Ctx) (*gatewaydomain.Gateway, error)
}

func NewGatewayResolver(finder appgateway.Finder, mode, baseDomain string) GatewayResolver {
	subdomain := NewSubdomainGatewayResolver(finder, baseDomain)
	if strings.ToLower(strings.TrimSpace(mode)) == gatewayDiscoveryModeSubdomain {
		return subdomain
	}
	return &HeaderGatewayResolver{finder: finder, hostFallback: subdomain}
}

type SubdomainGatewayResolver struct {
	finder     appgateway.Finder
	baseDomain string
}

func NewSubdomainGatewayResolver(finder appgateway.Finder, baseDomain string) GatewayResolver {
	baseDomain = strings.Trim(strings.ToLower(strings.TrimSpace(baseDomain)), ".")
	return &SubdomainGatewayResolver{
		finder:     finder,
		baseDomain: baseDomain,
	}
}

func (r *SubdomainGatewayResolver) Resolve(c *fiber.Ctx) (*gatewaydomain.Gateway, error) {
	slug, err := parseGatewaySlugFromHost(string(c.Request().Host()), r.baseDomain)
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
