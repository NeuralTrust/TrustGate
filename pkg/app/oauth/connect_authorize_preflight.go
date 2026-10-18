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
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// legacyAuthorizeAcceptTTL is how long an accepted authorize probe suppresses
// another probe of the same legacy slot. It is memory only (ENG-2190).
const legacyAuthorizeAcceptTTL = time.Hour

// healLegacyAuthorizeClient replaces one cached dynamic client registered
// before the issuer was recorded, when the authorize endpoint says that
// client_id is dead. The replacement is registered first. The legacy row is
// tombstoned only after that registration is stored, so a failed registration
// leaves the row the existing refresh grants still name. A redirect URI
// rejection does not replace the row: those grants may still be good
// (ENG-2190, ENG-2189).
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
	if s.legacyAuthorizeAccepted(slot) {
		return client, nil
	}
	prober, ok := s.registrar.(AuthorizePreflighter)
	if !ok || s.provider == nil {
		return client, nil
	}
	allowed := s.catalogAuthorizeURL(reg, cfg)
	rawURL, err := s.legacyAuthorizeProbeURL(cfg, reg, meta, client, redirectURI)
	if err != nil || !AuthorizeEndpointAllowed(rawURL, allowed) {
		return client, nil
	}
	probe, err := prober.PreflightAuthorize(ctx, rawURL, allowed)
	if err != nil {
		return client, nil
	}
	reason := classifyAuthorizePreflight(probe.Status, probe.Location, probe.Body, rawURL)
	switch {
	case reason == "":
		if authorizePreflightAccepted(probe.Status, probe.Location, rawURL) {
			s.rememberLegacyAuthorizeAccepted(slot)
		}
		return client, nil
	case authorizeDeadClient(reason):
		fresh, err := s.registrar.EnsureClient(ctx, clientCacheKey(gatewayID, reg, meta), meta, redirectURI)
		if err != nil {
			return nil, err
		}
		if err := s.registrar.DropCachedClient(ctx, slot, client.ClientID); err != nil {
			slog.Warn("oauth dcr: replacement client is stored; the legacy row could not be tombstoned",
				"code", catalogServerCode(reg, cfg),
				"slot", slotHash(slot),
				"reason", reason,
				"error", err)
			return fresh, nil
		}
		slog.Warn("oauth dcr: authorization server rejected a legacy client at authorize; replacing that cached client",
			"code", catalogServerCode(reg, cfg),
			"slot", slotHash(slot),
			"reason", reason)
		return fresh, nil
	case authorizeRedirectRejected(reason):
		slog.Warn("oauth dcr: authorization server rejected the cached client's redirect URI; leaving that client in place",
			"code", catalogServerCode(reg, cfg),
			"slot", slotHash(slot),
			"reason", reason)
		return nil, ErrLegacyAuthorizeRedirectRejected
	default:
		return client, nil
	}
}

func (s *connectService) legacyAuthorizeAccepted(slot string) bool {
	if s == nil || slot == "" {
		return false
	}
	now := s.now()
	s.authorizeAcceptedMu.Lock()
	defer s.authorizeAcceptedMu.Unlock()
	exp, ok := s.authorizeAccepted[slot]
	if !ok {
		return false
	}
	if !now.Before(exp) {
		delete(s.authorizeAccepted, slot)
		return false
	}
	return true
}

func (s *connectService) rememberLegacyAuthorizeAccepted(slot string) {
	if s == nil || slot == "" {
		return
	}
	now := s.now()
	s.authorizeAcceptedMu.Lock()
	defer s.authorizeAcceptedMu.Unlock()
	if s.authorizeAccepted == nil {
		s.authorizeAccepted = map[string]time.Time{}
	}
	for key, exp := range s.authorizeAccepted {
		if !now.Before(exp) {
			delete(s.authorizeAccepted, key)
		}
	}
	s.authorizeAccepted[slot] = now.Add(legacyAuthorizeAcceptTTL)
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

func (s *connectService) catalogAuthorizeURL(reg *registrydomain.Registry, cfg *registrydomain.MCPAuth) string {
	if s == nil || s.catalog == nil {
		return ""
	}
	entry, ok := s.catalog.GetByCode(catalogServerCode(reg, cfg))
	if !ok || entry.OAuth == nil {
		return ""
	}
	return strings.TrimSpace(entry.OAuth.AuthorizeURL)
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

// AuthorizeEndpointAllowed reports whether rawURL is an https request whose
// scheme, host, and port are the catalog authorize URL's. An omitted port is
// 443. Any other URL is refused so the preflight cannot be steered at another
// host (ENG-2190, ENG-2189).
func AuthorizeEndpointAllowed(rawURL, catalogAuthorizeURL string) bool {
	want, ok := authorizeEndpointOrigin(catalogAuthorizeURL)
	if !ok {
		return false
	}
	got, ok := authorizeEndpointOrigin(rawURL)
	return ok && got == want
}

func authorizeEndpointOrigin(raw string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" || !strings.EqualFold(parsed.Scheme, "https") {
		return "", false
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(strings.ToLower(parsed.Hostname()), port), true
}

func authorizeDeadClient(reason string) bool {
	switch reason {
	case "invalid_client", "unauthorized_client", "unrecognized_client":
		return true
	default:
		return false
	}
}

func authorizeRedirectRejected(reason string) bool {
	switch reason {
	case "invalid_redirect_uri", "redirect_uri":
		return true
	default:
		return false
	}
}

// A 3xx counts only when Location stays on the authorize URL's origin. A login
// page and the gateway callback are left alone. Any other status counts only
// for 400, 401, and 422 whose body is JSON; the raw body is never scanned
// (ENG-2190, ENG-2189).
func classifyAuthorizePreflight(status int, location, body, requestURL string) string {
	if status >= 300 && status < 400 {
		query, ok := authorizeLocationQuery(location, requestURL)
		if !ok {
			return ""
		}
		return authorizeRejectionSignal(query.Get("error"), query.Get("error_description"), "")
	}
	if status != 400 && status != 401 && status != 422 {
		return ""
	}
	code, description, message, ok := authorizeErrorFields(body)
	if !ok {
		return ""
	}
	return authorizeRejectionSignal(code, description, message)
}

// authorizePreflightAccepted is a response that shows the client is still
// usable: a 2xx, or a same-origin redirect that carries no error. Anything
// else, including an ambiguous 4xx, is not remembered.
func authorizePreflightAccepted(status int, location, requestURL string) bool {
	if status >= 200 && status < 300 {
		return true
	}
	if status < 300 || status >= 400 {
		return false
	}
	query, ok := authorizeLocationQuery(location, requestURL)
	if !ok {
		return false
	}
	return query.Get("error") == ""
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

func authorizeErrorFields(body string) (code, description, message string, ok bool) {
	var doc struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		Message          string `json:"message"`
	}
	if json.Unmarshal([]byte(body), &doc) != nil {
		return "", "", "", false
	}
	return doc.Error, doc.ErrorDescription, doc.Message, true
}

func authorizeRejectionSignal(code, description, message string) string {
	switch code {
	case "invalid_client":
		return "invalid_client"
	case "unauthorized_client":
		return "unauthorized_client"
	case "invalid_redirect_uri":
		return "invalid_redirect_uri"
	case "invalid_request":
		if mentionsRedirectURI(description) || mentionsRedirectURI(message) {
			return "redirect_uri"
		}
	}
	if mentionsUnrecognizedClient(description) || mentionsUnrecognizedClient(message) {
		return "unrecognized_client"
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
