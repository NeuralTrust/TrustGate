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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/url"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// healLegacyAuthorizeClient replaces one cached dynamic client registered
// before the issuer was recorded, when that client's authorize URL is rejected.
// A row that already records an issuer is not probed, so the replacement
// cannot be probed again (ENG-2190, ENG-2189).
func (s *connectService) healLegacyAuthorizeClient(
	ctx context.Context,
	gatewayID ids.GatewayID,
	reg *registrydomain.Registry,
	cfg *registrydomain.MCPAuth,
	slot string,
	meta *UpstreamAuthServer,
	client *RegisteredClient,
	redirectURI string,
) (*RegisteredClient, error) {
	if client == nil || client.Issuer != "" || slot == "" || slot != clientKey(gatewayID, reg) {
		return client, nil
	}
	if reg != nil && reg.MCPTarget != nil && reg.MCPTarget.HasURLVariables() {
		return client, nil
	}
	prober, ok := s.registrar.(AuthorizePreflighter)
	if !ok || s.provider == nil {
		return client, nil
	}
	allowedHost := s.catalogAuthorizeHost(reg, cfg)
	rawURL, err := s.legacyAuthorizeProbeURL(cfg, reg, meta, client, redirectURI)
	if err != nil || !authorizeURLHostAllowed(rawURL, allowedHost) {
		return client, nil
	}
	probe, err := prober.PreflightAuthorize(ctx, rawURL, allowedHost)
	if err != nil {
		return client, nil
	}
	reason := classifyAuthorizePreflight(probe.Status, probe.Location, probe.Body, rawURL)
	if reason == "" {
		return client, nil
	}
	if err := s.registrar.DropCachedClient(ctx, slot, client.ClientID); err != nil {
		return client, nil
	}
	slog.Warn("oauth dcr: authorization server rejected a legacy client at authorize; replacing that cached client",
		"code", catalogServerCode(reg, cfg),
		"slot", slotHash(slot),
		"reason", reason)
	return s.registrar.EnsureClient(ctx, clientCacheKey(gatewayID, reg, meta), meta, redirectURI)
}

func (s *connectService) legacyAuthorizeProbeURL(
	cfg *registrydomain.MCPAuth,
	reg *registrydomain.Registry,
	meta *UpstreamAuthServer,
	client *RegisteredClient,
	redirectURI string,
) (string, error) {
	state, err := randomToken()
	if err != nil {
		return "", err
	}
	verifier, err := randomToken()
	if err != nil {
		return "", err
	}
	auth := withIdentityScopes(autoAuth(applyCatalog(cfg, reg, s.catalog), meta, client))
	return s.provider.AuthorizeURL(auth, redirectURI, state, s256(verifier)), nil
}

func (s *connectService) catalogAuthorizeHost(reg *registrydomain.Registry, cfg *registrydomain.MCPAuth) string {
	if s == nil || s.catalog == nil {
		return ""
	}
	entry, ok := s.catalog.GetByCode(catalogServerCode(reg, cfg))
	if !ok || entry.OAuth == nil {
		return ""
	}
	return normalizedHostname(entry.OAuth.AuthorizeURL)
}

func catalogServerCode(reg *registrydomain.Registry, cfg *registrydomain.MCPAuth) string {
	if code := registryCode(reg); code != "" {
		return code
	}
	if cfg == nil {
		return ""
	}
	return strings.TrimSpace(cfg.Provider)
}

func slotHash(slot string) string {
	sum := sha256.Sum256([]byte(slot))
	return hex.EncodeToString(sum[:])
}

func authorizeURLHostAllowed(rawURL, allowedHost string) bool {
	if allowedHost == "" {
		return false
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https", "http":
	default:
		return false
	}
	return strings.EqualFold(parsed.Hostname(), allowedHost)
}

// A 3xx counts as a rejection only when Location stays on the authorize URL's
// origin. A login page and the gateway callback are left alone (ENG-2190).
func classifyAuthorizePreflight(status int, location, body, requestURL string) string {
	if status >= 300 && status < 400 {
		query, ok := authorizeLocationQuery(location, requestURL)
		if !ok {
			return ""
		}
		return authorizeRejectionSignal(query.Get("error"), query.Get("error_description"), "")
	}
	if status < 400 || status >= 500 {
		return ""
	}
	code, description, message := authorizeErrorFields(body)
	return authorizeRejectionSignal(code, description, message+"\n"+body)
}

func authorizeLocationQuery(location, requestURL string) (url.Values, bool) {
	base, err := url.Parse(requestURL)
	if err != nil || base.Hostname() == "" || location == "" {
		return nil, false
	}
	loc, err := url.Parse(location)
	if err != nil {
		return nil, false
	}
	resolved := base.ResolveReference(loc)
	if !strings.EqualFold(base.Scheme, resolved.Scheme) || !strings.EqualFold(base.Host, resolved.Host) {
		return nil, false
	}
	return resolved.Query(), true
}

func authorizeErrorFields(body string) (code, description, message string) {
	var doc struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		Message          string `json:"message"`
	}
	if json.Unmarshal([]byte(body), &doc) != nil {
		return "", "", ""
	}
	return doc.Error, doc.ErrorDescription, doc.Message
}

func authorizeRejectionSignal(code, description, extra string) string {
	switch code {
	case "invalid_client":
		return "invalid_client"
	case "unauthorized_client":
		return "unauthorized_client"
	case "invalid_redirect_uri":
		return "invalid_redirect_uri"
	case "invalid_request":
		if mentionsRedirectURI(description) {
			return "redirect_uri"
		}
	}
	if mentionsUnrecognizedClient(description) || mentionsUnrecognizedClient(extra) {
		return "unrecognized_client"
	}
	blob := strings.ToLower(description + "\n" + extra)
	if strings.Contains(blob, "invalid_redirect_uri") {
		return "invalid_redirect_uri"
	}
	return ""
}

func mentionsRedirectURI(s string) bool {
	s = strings.ToLower(s)
	return strings.Contains(s, "redirect_uri") || strings.Contains(s, "redirect uri")
}

func mentionsUnrecognizedClient(s string) bool {
	s = strings.ToLower(s)
	if !strings.Contains(s, "client") {
		return false
	}
	return strings.Contains(s, "unrecognized") || strings.Contains(s, "unknown")
}
