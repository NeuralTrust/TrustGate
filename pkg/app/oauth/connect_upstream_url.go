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

package oauth

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// ErrUpstreamSetupRequired is returned when a server's address is a template
// whose values this principal has not given yet ({region}, {domain}): there is
// no upstream to discover an OAuth server at until they do.
var ErrUpstreamSetupRequired = fmt.Errorf(
	"oauth connect: this server's address is not complete: finish its setup before connecting: %w",
	commonerrors.ErrValidation)

// ErrUnresolvedOAuthPlaceholder is returned when the authorize URL, the token
// URL, or the resource indicator still contains a `{placeholder}` after this
// instance's URL variables are applied. The browser is not redirected.
var ErrUnresolvedOAuthPlaceholder = fmt.Errorf(
	"oauth connect: the authorization URL still has an unresolved placeholder, so the browser was not redirected: %w",
	commonerrors.ErrValidation)

// ErrOAuthURLHost is returned when a per-user URL variable would send the
// authorize redirect or the token request to a host other than the one already
// resolved and validated for this server. The browser is not redirected, and
// the client secret is not sent.
var ErrOAuthURLHost = fmt.Errorf(
	"oauth connect: the authorization URL does not match this server, so the browser was not redirected: %w",
	commonerrors.ErrValidation)

// discover finds the upstream's OAuth server at the URL the principal will
// actually dial. A templated URL was handed to discovery as-is, so every
// {variable} server failed with "bad upstream url" even after its values were
// given (RUN-1636).
func (s *connectService) discover(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	reg *registrydomain.Registry,
) (*UpstreamAuthServer, error) {
	upstream, err := s.upstreamURL(ctx, gatewayID, principalSub, reg)
	if err != nil {
		return nil, err
	}
	return s.registrar.Discover(ctx, upstream)
}

// upstreamURL resolves a registry's URL for one principal with the values the
// dial path uses, and holds the result to the dial path's SSRF gate: discovery
// fetches from that host, so a URL assembled from per-user values must be public
// here as well. A URL with no placeholders is returned unchanged.
func (s *connectService) upstreamURL(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	reg *registrydomain.Registry,
) (string, error) {
	target := reg.MCPTarget
	if target == nil || !target.HasURLVariables() {
		if target == nil {
			return "", nil
		}
		return target.URL, nil
	}
	values, err := s.principalURLValues(ctx, gatewayID, principalSub, reg)
	if err != nil {
		return "", err
	}
	resolved, err := registrydomain.ResolveURL(target.URL, target.URLVariables, values)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUpstreamSetupRequired, err)
	}
	if err := registrydomain.ValidateResolvedUpstreamHost(resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

// principalURLValues is the per-user placeholder map the dial path uses:
// instance config, replaced by the principal's stored values when those are
// available. A nil target must not reach here.
func (s *connectService) principalURLValues(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	reg *registrydomain.Registry,
) (map[string]string, error) {
	values := reg.MCPTarget.InstanceConfig
	if s.urlValues != nil && principalSub != "" {
		v, err := s.urlValues.Values(ctx, gatewayID, principalSub, reg)
		if err != nil {
			return nil, err
		}
		values = v
	}
	return values, nil
}

// finalizeAuthURLs applies this instance's URL variables to the resource
// indicator and to any authorize, token, or userinfo URL that still carries a
// placeholder, then refuses to redirect while one remains.
//
// A templated server stores the resource as the server template (catalog
// resource_metadata copies the URL). Discovery already runs at the resolved
// URL, so its protected-resource `resource` wins over that template. The
// stored resource is left alone: the vault key fingerprints it as written.
//
// A placeholder in the host is a per-user value. The resulting host has to be
// the one already resolved and validated for this server, so the value cannot
// aim the redirect or the token request (where the client secret goes) at
// another host.
func (s *connectService) finalizeAuthURLs(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	reg *registrydomain.Registry,
	cfg *registrydomain.MCPAuth,
	meta *UpstreamAuthServer,
) (*registrydomain.MCPAuth, error) {
	if cfg == nil || !hasOAuthPlaceholder(cfg) {
		return cfg, nil
	}
	out := *cfg
	if meta != nil && strings.ContainsAny(out.Resource, "{}") {
		if prm := strings.TrimSpace(meta.Resource); prm != "" {
			out.Resource = prm
		}
	}
	if !hasOAuthPlaceholder(&out) {
		return s.finishResolvedAuth(reg, &out)
	}
	if reg == nil || reg.MCPTarget == nil {
		return nil, ErrUnresolvedOAuthPlaceholder
	}
	resolved, err := s.upstreamURL(ctx, gatewayID, principalSub, reg)
	if err != nil {
		return nil, err
	}
	values, err := s.principalURLValues(ctx, gatewayID, principalSub, reg)
	if err != nil {
		return nil, err
	}
	vars := reg.MCPTarget.URLVariables
	resolvedHost := normalizedHostname(resolved)
	for _, field := range []*string{&out.AuthorizeURL, &out.TokenURL, &out.UserinfoURL} {
		rewritten, err := substituteContactURL(*field, resolvedHost, vars, values)
		if err != nil {
			return nil, err
		}
		*field = rewritten
	}
	if strings.ContainsAny(out.Resource, "{}") {
		substituted, err := registrydomain.ResolveURL(out.Resource, vars, values)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnresolvedOAuthPlaceholder, err)
		}
		out.Resource = substituted
	}
	return s.finishResolvedAuth(reg, &out)
}

func (s *connectService) finishResolvedAuth(reg *registrydomain.Registry, cfg *registrydomain.MCPAuth) (*registrydomain.MCPAuth, error) {
	cfg = withholdSharedSecret(cfg, reg, s.sharedOAuth)
	if hasOAuthPlaceholder(cfg) {
		return nil, ErrUnresolvedOAuthPlaceholder
	}
	return cfg, nil
}

func hasOAuthPlaceholder(cfg *registrydomain.MCPAuth) bool {
	return strings.ContainsAny(cfg.AuthorizeURL, "{}") ||
		strings.ContainsAny(cfg.TokenURL, "{}") ||
		strings.ContainsAny(cfg.UserinfoURL, "{}") ||
		strings.ContainsAny(cfg.Resource, "{}")
}

// substituteContactURL fills placeholders in a URL the gateway contacts.
// When the host itself is templated, the filled host must be resolvedHost:
// that is the host ValidateResolvedUpstreamHost already accepted.
func substituteContactURL(raw, resolvedHost string, vars []registrydomain.MCPURLVariable, values map[string]string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.ContainsAny(raw, "{}") {
		return raw, nil
	}
	templatedHost := hostHasPlaceholder(raw)
	resolved, err := registrydomain.ResolveURL(raw, vars, values)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnresolvedOAuthPlaceholder, err)
	}
	if !templatedHost {
		return resolved, nil
	}
	parsed, err := url.Parse(resolved)
	if err != nil || parsed == nil || parsed.User != nil || normalizedHostname(resolved) == "" || normalizedHostname(resolved) != resolvedHost {
		return "", ErrOAuthURLHost
	}
	return resolved, nil
}

// hostHasPlaceholder reports whether a per-user value chooses the host.
// `{` in the host makes url.Parse fail, which is itself that case.
func hostHasPlaceholder(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil {
		return strings.ContainsAny(raw, "{}")
	}
	return strings.ContainsAny(parsed.Host, "{}")
}

func normalizedHostname(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
}
