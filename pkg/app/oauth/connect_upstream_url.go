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

	"golang.org/x/net/publicsuffix"

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
// authorize redirect or the token request somewhere this server's declaration
// does not allow. The browser is not redirected, and the client secret is not
// sent. The rejected host is not included.
var ErrOAuthURLHost = fmt.Errorf(
	"oauth connect: the authorization URL does not match this server, so the browser was not redirected: %w",
	commonerrors.ErrValidation)

// discover finds the upstream's OAuth server at the URL the principal will
// actually dial. A templated URL was handed to discovery as-is, so every
// {variable} server failed with "bad upstream url" even after its values were
// given (RUN-1636).
//
// A protected-resource `resource` is kept only when its canonical form is the
// URL discovery was made for (RFC 9728 §3.3). Every caller reads it from here,
// so an empty stored resource never adopts another one.
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
	meta, err := s.registrar.Discover(ctx, upstream)
	if err != nil || meta == nil {
		return meta, err
	}
	if prm := strings.TrimSpace(meta.Resource); prm != "" && !registrydomain.SameCanonicalResource(prm, upstream) {
		out := *meta
		out.Resource = ""
		return &out, nil
	}
	return meta, nil
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
// resource_metadata copies the URL). A protected-resource `resource` replaces
// that template only when its canonical form is the resolved upstream URL
// (RFC 9728 §3.3). The stored resource is left alone: the vault key
// fingerprints it as written.
//
// A placeholder in a path or query is filled and sent. A placeholder that is
// only part of the host must resolve to the same scheme, host, and port as
// the upstream URL. A placeholder that is the whole host is a value the user
// chose, so matching that host proves nothing: it is allowed only when every
// such variable is closed (Options) or the resolved host matches a suffix the
// variable declares. Otherwise the redirect and the token request — where the
// client secret goes — are refused before either leaves.
func (s *connectService) finalizeAuthURLs(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	reg *registrydomain.Registry,
	cfg *registrydomain.MCPAuth,
	meta *UpstreamAuthServer,
) (*registrydomain.MCPAuth, error) {
	if cfg == nil {
		return nil, nil
	}
	vars := s.hostBoundURLVariables(reg)
	if err := s.refuseOpenWholeHostDiscovery(ctx, gatewayID, principalSub, reg, cfg, meta, vars); err != nil {
		return nil, err
	}
	if !hasOAuthPlaceholder(cfg) {
		return s.finishResolvedAuth(reg, cfg)
	}
	if reg == nil || reg.MCPTarget == nil {
		return nil, ErrUnresolvedOAuthPlaceholder
	}
	resolved, err := s.upstreamURL(ctx, gatewayID, principalSub, reg)
	if err != nil {
		return nil, err
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
	values, err := s.principalURLValues(ctx, gatewayID, principalSub, reg)
	if err != nil {
		return nil, err
	}
	for _, field := range []*string{&out.AuthorizeURL, &out.TokenURL, &out.UserinfoURL} {
		rewritten, err := substituteContactURL(*field, resolved, vars, values)
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

// refuseOpenWholeHostDiscovery applies the whole-host rule to a manual
// registry whose token URL was not pinned. manualAuth fills that URL from
// metadata discovered on the user-chosen host, and the client secret is posted
// there. A closed variable or a declared host suffix is the only bound that
// is not the user's own input.
func (s *connectService) refuseOpenWholeHostDiscovery(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	reg *registrydomain.Registry,
	cfg *registrydomain.MCPAuth,
	meta *UpstreamAuthServer,
	vars []registrydomain.MCPURLVariable,
) error {
	// Dynamic registration mints its client at the authorization server
	// discovery just found, so the connect and refresh paths may post that
	// secret back to it. Revocation is not that case: the cached client is
	// posted to whatever endpoint the document names, and RevocationMaterial
	// applies refuseUnboundUserChosenHost before returning one.
	if cfg.Registration == registrydomain.RegistrationAuto || meta == nil || reg == nil || reg.MCPTarget == nil {
		return nil
	}
	return s.refuseUnboundUserChosenHost(ctx, gatewayID, principalSub, reg, vars)
}

// refuseUnboundUserChosenHost returns ErrOAuthURLHost when a per-user value
// picks the registrable domain and neither a closed variable nor a declared
// suffix bounds it. The caller must not have sent a client secret yet.
func (s *connectService) refuseUnboundUserChosenHost(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	reg *registrydomain.Registry,
	vars []registrydomain.MCPURLVariable,
) error {
	if reg == nil || reg.MCPTarget == nil {
		return nil
	}
	names, chosen := userChosenHostNames(reg.MCPTarget.URL)
	if !chosen {
		return nil
	}
	if hostVariablesClosed(names, vars) {
		return nil
	}
	resolved, err := s.upstreamURL(ctx, gatewayID, principalSub, reg)
	if err != nil {
		return err
	}
	if declaredSuffixMatches(normalizedHostname(resolved), names, vars) {
		return nil
	}
	return ErrOAuthURLHost
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
// Path and query placeholders are filled as written. A templated host must
// share the resolved upstream's scheme, host, and port. When the placeholder
// is the whole host, that match is not enough: the variable has to be closed
// or the host has to match a declared suffix.
func substituteContactURL(raw, resolvedUpstream string, vars []registrydomain.MCPURLVariable, values map[string]string) (string, error) {
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
	names, chosen := userChosenHostNames(raw)
	if chosen && !hostVariablesClosed(names, vars) && !declaredSuffixMatches(normalizedHostname(resolved), names, vars) {
		return "", ErrOAuthURLHost
	}
	if !sameContactOrigin(resolved, resolvedUpstream) {
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

// userChosenHostNames reports the placeholders in a URL's hostname when a
// per-user value can pick the registrable domain. The host is pinned only
// when the labels to the right of the last placeholder are literal and hold a
// registrable domain (`{domain}.aha.io`, `{tenant}-be.glean.com`). A value
// that is the whole host, or that sits next to the public suffix
// (`mcp.{domain}`, `api-{domain}`, `{a}.{b}.com`), chooses where the request
// goes.
func userChosenHostNames(raw string) ([]string, bool) {
	host, ok := templateHostname(raw)
	if !ok || !strings.Contains(host, "{") {
		return nil, false
	}
	names, _ := splitPlaceholders(host)
	if len(names) == 0 {
		return nil, false
	}
	return names, !literalRegistrableSuffix(host)
}

// literalRegistrableSuffix reports whether the complete labels after the
// last placeholder contain a registrable domain. The label that holds the
// placeholder is skipped even when it has literal text after it.
func literalRegistrableSuffix(host string) bool {
	end := strings.LastIndex(host, "}")
	if end < 0 {
		return false
	}
	rest := host[end+1:]
	dot := strings.IndexByte(rest, '.')
	if dot < 0 {
		return false
	}
	literal := strings.ToLower(strings.Trim(rest[dot+1:], "."))
	if literal == "" || strings.ContainsAny(literal, "{}") {
		return false
	}
	_, err := publicsuffix.EffectiveTLDPlusOne(literal)
	return err == nil
}

// templateHostname is the hostname of a URL template. `{` in the host makes
// url.Parse fail, so the host is taken from the text in that case. A literal
// port is not part of the name.
func templateHostname(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if parsed, err := url.Parse(raw); err == nil && parsed != nil && parsed.Hostname() != "" && !strings.Contains(parsed.Hostname(), "{") {
		return parsed.Hostname(), true
	}
	const schemeSep = "://"
	i := strings.Index(raw, schemeSep)
	if i < 0 {
		return "", false
	}
	rest := raw[i+len(schemeSep):]
	if at := strings.Index(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	end := len(rest)
	for j, c := range rest {
		if c == '/' || c == '?' || c == '#' {
			end = j
			break
		}
	}
	hostport := rest[:end]
	if hostport == "" {
		return "", false
	}
	if colon := strings.LastIndex(hostport, ":"); colon >= 0 && !strings.Contains(hostport[colon:], "}") {
		return hostport[:colon], true
	}
	return hostport, true
}

// splitPlaceholders returns the {name} tokens in host and the text that is
// not one of those tokens.
func splitPlaceholders(host string) ([]string, string) {
	var names []string
	var rest strings.Builder
	for i := 0; i < len(host); {
		if host[i] != '{' {
			rest.WriteByte(host[i])
			i++
			continue
		}
		end := strings.IndexByte(host[i:], '}')
		if end <= 1 {
			rest.WriteByte(host[i])
			i++
			continue
		}
		name := host[i+1 : i+end]
		if !placeholderName(name) {
			rest.WriteString(host[i : i+end+1])
			i += end + 1
			continue
		}
		names = append(names, name)
		i += end + 1
	}
	return names, rest.String()
}

func placeholderName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

func hostVariablesClosed(names []string, vars []registrydomain.MCPURLVariable) bool {
	if len(names) == 0 {
		return false
	}
	byName := variablesByName(vars)
	for _, name := range names {
		v, ok := byName[name]
		if !ok || !v.HasOptions() {
			return false
		}
	}
	return true
}

func declaredSuffixMatches(host string, names []string, vars []registrydomain.MCPURLVariable) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}
	byName := variablesByName(vars)
	for _, name := range names {
		v, ok := byName[name]
		if !ok {
			continue
		}
		for _, suffix := range validHostSuffixes(v.HostSuffix) {
			if hostUnderSuffix(host, suffix) {
				return true
			}
		}
	}
	return false
}

// hostBoundURLVariables is the variable list the host check uses. When the
// registry's code is a catalog code, the catalog entry for that code is the
// bound: a registry copied before host_suffix existed stores an empty list
// and gets the catalog's, and a stored list can only narrow the catalog's,
// never widen it. A variable the catalog gives no suffix has none here,
// whatever the row stores. A registry whose code is not in the catalog keeps
// its stored list. The stored registry is not modified.
func (s *connectService) hostBoundURLVariables(reg *registrydomain.Registry) []registrydomain.MCPURLVariable {
	if reg == nil || reg.MCPTarget == nil {
		return nil
	}
	vars := reg.MCPTarget.URLVariables
	fromCatalog, ok := s.catalogHostSuffixes(reg)
	if !ok || len(vars) == 0 {
		return vars
	}
	out := make([]registrydomain.MCPURLVariable, len(vars))
	copy(out, vars)
	for i := range out {
		out[i].HostSuffix = narrowHostSuffixes(fromCatalog[out[i].Name], out[i].HostSuffix)
	}
	return out
}

// catalogHostSuffixes returns the catalog entry's suffixes by variable name,
// read only from the entry for the registry's own code. ok is false when the
// code is empty or not a catalog code.
func (s *connectService) catalogHostSuffixes(reg *registrydomain.Registry) (map[string][]string, bool) {
	if s == nil || s.catalog == nil || reg == nil || reg.MCPTarget == nil {
		return nil, false
	}
	code := strings.TrimSpace(reg.MCPTarget.Code)
	if code == "" {
		return nil, false
	}
	entry, ok := s.catalog.GetByCode(code)
	if !ok {
		return nil, false
	}
	out := make(map[string][]string, len(entry.URLVariables))
	for _, v := range entry.URLVariables {
		if suffixes := validHostSuffixes(v.HostSuffix); len(suffixes) > 0 {
			out[v.Name] = suffixes
		}
	}
	return out, true
}

// narrowHostSuffixes is the set of hosts both lists allow. An empty stored
// list takes the catalog's. A stored suffix outside every catalog suffix is
// dropped; a catalog suffix under a stored one is kept.
func narrowHostSuffixes(catalog, stored []string) []string {
	if len(catalog) == 0 {
		return nil
	}
	stored = validHostSuffixes(stored)
	if len(stored) == 0 {
		return catalog
	}
	var out []string
	seen := make(map[string]struct{})
	add := func(suffix string) {
		if _, dup := seen[suffix]; !dup {
			seen[suffix] = struct{}{}
			out = append(out, suffix)
		}
	}
	for _, st := range stored {
		for _, c := range catalog {
			switch {
			case hostUnderSuffix(st, c):
				add(st)
			case hostUnderSuffix(c, st):
				add(c)
			}
		}
	}
	return out
}

func validHostSuffixes(in []string) []string {
	var out []string
	for _, raw := range in {
		if suffix := normalizeHostSuffix(raw); suffix != "" {
			out = append(out, suffix)
		}
	}
	return out
}

func hostUnderSuffix(host, suffix string) bool {
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}

func cloneHostSuffixes(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, suffix := range in {
		suffix = strings.TrimSpace(suffix)
		if suffix == "" {
			continue
		}
		out = append(out, suffix)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func variablesByName(vars []registrydomain.MCPURLVariable) map[string]registrydomain.MCPURLVariable {
	out := make(map[string]registrydomain.MCPURLVariable, len(vars))
	for _, v := range vars {
		out[v.Name] = v
	}
	return out
}

// normalizeHostSuffix returns the suffix to match against, or "" when it is
// not a usable bound: fewer than two labels, or a public suffix (`com`,
// `co.uk`, `github.io`) under which anyone can register a host.
func normalizeHostSuffix(raw string) string {
	suffix := strings.ToLower(strings.TrimSpace(raw))
	suffix = strings.TrimPrefix(suffix, "*.")
	suffix = strings.Trim(suffix, ".")
	if suffix == "" || strings.ContainsAny(suffix, "*{}/:@ ") || strings.Count(suffix, ".") < 1 {
		return ""
	}
	if ps, _ := publicsuffix.PublicSuffix(suffix); ps == suffix {
		return ""
	}
	return suffix
}

// sameContactOrigin compares scheme, hostname, and port. An empty port is the
// scheme's default, so https://host and https://host:443 are the same origin.
// A URL with userinfo is not an origin the gateway will contact.
func sameContactOrigin(contact, upstream string) bool {
	cs, ch, cp, okContact := contactOrigin(contact)
	us, uh, up, okUpstream := contactOrigin(upstream)
	return okContact && okUpstream && cs == us && ch == uh && cp == up
}

func contactOrigin(raw string) (scheme, host, port string, ok bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil || parsed.User != nil {
		return "", "", "", false
	}
	scheme = strings.ToLower(parsed.Scheme)
	host = strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" || (scheme != "http" && scheme != "https") {
		return "", "", "", false
	}
	port = parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return scheme, host, port, true
}
