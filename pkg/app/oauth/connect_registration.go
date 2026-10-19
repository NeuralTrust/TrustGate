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
	"fmt"
	"net/url"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/app/mcpoauth"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func (s *connectService) effectiveAuth(ctx context.Context, baseURL string, gatewayID ids.GatewayID, principalSub string, reg *registrydomain.Registry) (*registrydomain.MCPAuth, error) {
	cfg := forwardedAuth(reg)
	if cfg == nil {
		return nil, ErrProviderNotFound
	}
	if cfg.Registration != registrydomain.RegistrationAuto {
		resolved, resolveErr := s.resolveUpstream(ctx, gatewayID, principalSub, reg)
		catalogRes := upstreamResolution{}
		if resolveErr == nil {
			catalogRes = resolved
		}
		effective := withIdentityScopes(applyCatalog(applySharedOAuth(cfg, reg, s.sharedOAuth), reg, s.catalog, catalogRes))
		if effective.AuthorizeURL != "" && effective.TokenURL != "" {
			return s.finalizeAuthURLs(ctx, gatewayID, principalSub, reg, effective, nil, catalogRes)
		}
		if resolveErr != nil {
			return nil, resolveErr
		}
		meta, err := s.discover(ctx, gatewayID, principalSub, reg, resolved)
		if err != nil {
			return nil, err
		}
		// withholdSharedSecret runs inside finalizeAuthURLs, after substitution.
		return s.finalizeAuthURLs(ctx, gatewayID, principalSub, reg, manualAuth(effective, meta), meta, resolved)
	}
	res, err := s.resolveUpstream(ctx, gatewayID, principalSub, reg)
	if err != nil {
		return nil, err
	}
	meta, err := s.discover(ctx, gatewayID, principalSub, reg, res)
	if err != nil {
		return nil, err
	}
	slot, err := s.ClientSlot(ctx, gatewayID, reg, meta)
	if err != nil {
		return nil, err
	}
	redirectURI := connectCallbackURL(baseURL, cfg.Provider)
	client, err := s.registrar.EnsureClient(ctx, slot, meta, redirectURI)
	if err != nil {
		return nil, err
	}
	client, err = s.healLegacyAuthorizeClient(ctx, gatewayID, reg, cfg, slot, meta, client, redirectURI, res)
	if err != nil {
		return nil, err
	}
	return s.finalizeAuthURLs(ctx, gatewayID, principalSub, reg, withIdentityScopes(autoAuth(applyCatalog(cfg, reg, s.catalog, res), meta, client)), meta, res)
}

// exchangeAuth builds the token-endpoint configuration for a code that was
// minted for clientID. It does not register a client: an in-flight callback
// must redeem the code with the client that started the flow.
func (s *connectService) exchangeAuth(
	ctx context.Context,
	baseURL string,
	gatewayID ids.GatewayID,
	principalSub string,
	reg *registrydomain.Registry,
	clientID string,
) (*registrydomain.MCPAuth, error) {
	cfg := forwardedAuth(reg)
	if cfg == nil {
		return nil, ErrProviderNotFound
	}
	if cfg.Registration != registrydomain.RegistrationAuto || clientID == "" {
		return s.effectiveAuth(ctx, baseURL, gatewayID, principalSub, reg)
	}
	res, err := s.resolveUpstream(ctx, gatewayID, principalSub, reg)
	if err != nil {
		return nil, err
	}
	meta, err := s.discover(ctx, gatewayID, principalSub, reg, res)
	if err != nil {
		return nil, err
	}
	slot, err := s.ClientSlot(ctx, gatewayID, reg, meta)
	if err != nil {
		return nil, err
	}
	cached, err := s.registrar.CachedClient(ctx, slot)
	if err != nil {
		return nil, err
	}
	if cached == nil || cached.ClientID != clientID {
		return nil, fmt.Errorf("%w: client %q", ErrNoRegisteredClient, clientID)
	}
	auth, err := s.finalizeAuthURLs(ctx, gatewayID, principalSub, reg, withIdentityScopes(autoAuth(applyCatalog(cfg, reg, s.catalog, res), meta, cached)), meta, res)
	if err != nil || auth == nil {
		return auth, err
	}
	auth.ClientSlot = slot
	return auth, nil
}

// RevocationMaterial is the OAuth client a refresh would present, plus the
// revocation endpoint from the authorization-server document that supplied
// TokenURL. RevocationEndpoint is empty for a pinned registry (AuthorizeURL
// and TokenURL both configured). Those registries do not revoke: nothing on
// the registry stores a revocation URL, and uninstall does not discover one.
type RevocationMaterial struct {
	ClientID                string
	ClientSecret            string
	TokenEndpointAuthMethod string
	TokenURL                string
	RevocationEndpoint      string
}

func (s *connectService) RefreshAuth(ctx context.Context, gatewayID ids.GatewayID, reg *registrydomain.Registry) (*registrydomain.MCPAuth, error) {
	// A refresh runs on the dial path, as the principal the call is for.
	principalSub := ""
	if p := identity.PrincipalFromContext(ctx); p != nil {
		principalSub = p.Subject
	}
	auth, _, _, err := s.refreshMaterial(ctx, gatewayID, principalSub, reg)
	return auth, err
}

// RevocationMaterial builds the client RefreshAuth would use. A pinned
// authorize/token pair does not revoke and is not discovered.
func (s *connectService) RevocationMaterial(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	reg *registrydomain.Registry,
) (*RevocationMaterial, error) {
	auth, revocationEndpoint, res, err := s.refreshMaterial(ctx, gatewayID, principalSub, reg)
	if err != nil || auth == nil {
		return nil, err
	}
	// refreshMaterial skips the host check for dynamic registration, because
	// that client was minted by the discovered server. A revocation POST sends
	// the same secret — admin or DCR — to the endpoint that document names, so
	// an unbound user-chosen host is refused before either leaves. The check
	// uses the resolution discovery used, not a second read of the install.
	if revocationEndpoint != "" {
		if err := s.refuseUnboundUserChosenHost(ctx, gatewayID, principalSub, reg, s.hostBoundURLVariables(reg), res); err != nil {
			return nil, err
		}
	}
	return &RevocationMaterial{
		ClientID:                auth.ClientID,
		ClientSecret:            auth.ClientSecret,
		TokenEndpointAuthMethod: auth.TokenEndpointAuthMethod,
		TokenURL:                auth.TokenURL,
		RevocationEndpoint:      revocationEndpoint,
	}, nil
}

// refreshMaterial is the auth RefreshAuth returns, and the revocation endpoint
// from that same discovery. The endpoint is empty when the authorize and token
// URLs are already configured: a pinned registry does not revoke.
func (s *connectService) refreshMaterial(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	reg *registrydomain.Registry,
) (*registrydomain.MCPAuth, string, upstreamResolution, error) {
	cfg := forwardedAuth(reg)
	if cfg == nil {
		return nil, "", upstreamResolution{}, ErrProviderNotFound
	}
	if cfg.Registration != registrydomain.RegistrationAuto {
		resolved, resolveErr := s.resolveUpstream(ctx, gatewayID, principalSub, reg)
		catalogRes := upstreamResolution{}
		if resolveErr == nil {
			catalogRes = resolved
		}
		effective := withIdentityScopes(applyCatalog(applySharedOAuth(cfg, reg, s.sharedOAuth), reg, s.catalog, catalogRes))
		if effective.AuthorizeURL != "" && effective.TokenURL != "" {
			auth, err := s.finalizeAuthURLs(ctx, gatewayID, principalSub, reg, effective, nil, catalogRes)
			return auth, "", upstreamResolution{}, err
		}
		if resolveErr != nil {
			return nil, "", upstreamResolution{}, resolveErr
		}
		meta, err := s.discover(ctx, gatewayID, principalSub, reg, resolved)
		if err != nil {
			return nil, "", upstreamResolution{}, err
		}
		// withholdSharedSecret runs inside finalizeAuthURLs, after substitution.
		return s.finalizedRefresh(ctx, gatewayID, principalSub, reg, manualAuth(effective, meta), meta, resolved)
	}
	res, err := s.resolveUpstream(ctx, gatewayID, principalSub, reg)
	if err != nil {
		return nil, "", upstreamResolution{}, err
	}
	meta, err := s.discover(ctx, gatewayID, principalSub, reg, res)
	if err != nil {
		return nil, "", upstreamResolution{}, err
	}
	client, slot, err := s.clientForRefresh(ctx, gatewayID, principalSub, reg, meta)
	if err != nil {
		return nil, "", upstreamResolution{}, err
	}
	if client == nil {
		return nil, "", upstreamResolution{}, fmt.Errorf("%w: provider %q", ErrNoRegisteredClient, cfg.Provider)
	}
	auth, endpoint, res, err := s.finalizedRefresh(ctx, gatewayID, principalSub, reg, withIdentityScopes(autoAuth(applyCatalog(cfg, reg, s.catalog, res), meta, client)), meta, res)
	if auth != nil {
		auth.ClientSlot = slot
	}
	return auth, endpoint, res, err
}

func (s *connectService) finalizedRefresh(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	reg *registrydomain.Registry,
	cfg *registrydomain.MCPAuth,
	meta *UpstreamAuthServer,
	res upstreamResolution,
) (*registrydomain.MCPAuth, string, upstreamResolution, error) {
	auth, err := s.finalizeAuthURLs(ctx, gatewayID, principalSub, reg, cfg, meta, res)
	if err != nil {
		return nil, "", upstreamResolution{}, err
	}
	return auth, revocationEndpointOf(meta), res, nil
}

func revocationEndpointOf(meta *UpstreamAuthServer) string {
	if meta == nil {
		return ""
	}
	return strings.TrimSpace(meta.RevocationEndpoint)
}

func applySharedOAuth(cfg *registrydomain.MCPAuth, reg *registrydomain.Registry, shared mcpoauth.Provider) *registrydomain.MCPAuth {
	if cfg == nil {
		return cfg
	}
	creds, ok := mcpoauth.SharedClientFor(shared, sharedClientQuery(cfg, reg, false))
	if !ok {
		return cfg
	}
	out := *cfg
	out.ClientID = creds.ClientID
	out.ClientSecret = creds.ClientSecret
	return &out
}

// withholdSharedSecret drops the platform's shared client secret from a
// configuration whose endpoints were discovered rather than configured.
// applySharedOAuth accepts empty endpoints, so it cannot know where discovery
// will point; the secret only goes to the provider's own authorization server.
func withholdSharedSecret(cfg *registrydomain.MCPAuth, reg *registrydomain.Registry, shared mcpoauth.Provider) *registrydomain.MCPAuth {
	if cfg == nil || shared == nil || cfg.ClientSecret == "" {
		return cfg
	}
	creds, ok := shared.CredentialsFor(mcpoauth.SharedCode(registryCode(reg), cfg.Provider))
	if !ok || cfg.ClientSecret != creds.ClientSecret {
		return cfg
	}
	if _, allowed := mcpoauth.SharedClientFor(shared, sharedClientQuery(cfg, reg, true)); allowed {
		return cfg
	}
	out := *cfg
	out.ClientSecret = ""
	return &out
}

func sharedClientQuery(cfg *registrydomain.MCPAuth, reg *registrydomain.Registry, strict bool) mcpoauth.SharedClientQuery {
	return mcpoauth.SharedClientQuery{
		Code:         registryCode(reg),
		Provider:     cfg.Provider,
		ClientID:     cfg.ClientID,
		AuthorizeURL: cfg.AuthorizeURL,
		TokenURL:     cfg.TokenURL,
		Strict:       strict,
	}
}

func registryCode(reg *registrydomain.Registry) string {
	if reg == nil || reg.MCPTarget == nil {
		return ""
	}
	return reg.MCPTarget.Code
}

// applyCatalog lets the curated catalog correct the scopes and resource
// indicator persisted on a registry. Both registration paths need it: these are
// copied onto the registry when it is created, so a registry created against an
// older catalog keeps asking for scopes the upstream may since have dropped, or
// naming a resource its authorization server rejects with invalid_target (Axiom
// only accepts its root resource), and nothing else ever rewrites them.
//
// The correction is applied only when this row's resolved upstream URL is the
// catalog server URL. A self-hosted install of the same catalog code (an old
// Cube row whose {cube_host} resolves somewhere other than cubecloud.dev) keeps
// the resource and scopes it stored. Sending the hosted resource to that
// authorization server fails with invalid_target. res is the resolution this
// flow already computed; a not-ready resolution does not match.
func applyCatalog(cfg *registrydomain.MCPAuth, reg *registrydomain.Registry, cat authCatalog, res upstreamResolution) *registrydomain.MCPAuth {
	if cfg == nil || cat == nil {
		return cfg
	}
	code := ""
	if reg != nil && reg.MCPTarget != nil {
		code = strings.TrimSpace(reg.MCPTarget.Code)
	}
	if code == "" {
		code = strings.TrimSpace(cfg.Provider)
	}
	entry, ok := cat.GetByCode(code)
	if !ok || entry.OAuth == nil {
		return cfg
	}
	resource := strings.TrimSpace(entry.OAuth.Resource)
	if catalogServerMatches(entry, res) && (len(entry.OAuth.Scopes) > 0 || resource != "") {
		out := *cfg
		if len(entry.OAuth.Scopes) > 0 {
			out.Scopes = append([]string(nil), entry.OAuth.Scopes...)
		}
		if resource != "" {
			out.Resource = resource
		}
		return &out
	}
	return regionOptionScopes(cfg, entry, res)
}

// regionOptionScopes copies catalog scopes onto the authorize request when the
// resolved instance URL is one published region of this catalog entry. The
// registry row is not written. A manual registration with its own non-empty
// scope list is an admin OAuth app and keeps those scopes. This is not a
// re-apply of the rest of the catalog (URL, resource, registration).
func regionOptionScopes(cfg *registrydomain.MCPAuth, entry catalogdomain.MCPServer, res upstreamResolution) *registrydomain.MCPAuth {
	if cfg == nil || entry.OAuth == nil || len(entry.OAuth.Scopes) == 0 || !res.ready {
		return cfg
	}
	if cfg.Registration == registrydomain.RegistrationManual && hasScope(cfg.Scopes) {
		return cfg
	}
	if !catalogOptionURLMatches(entry, res.url) {
		return cfg
	}
	out := *cfg
	out.Scopes = append([]string(nil), entry.OAuth.Scopes...)
	return &out
}

func hasScope(scopes []string) bool {
	for _, scope := range scopes {
		if strings.TrimSpace(scope) != "" {
			return true
		}
	}
	return false
}

// catalogOptionExpansionCap bounds how many closed-option combinations a
// templated catalog URL is expanded to. Region lists are a handful of values.
const catalogOptionExpansionCap = 64

// catalogServerMatches reports whether the row's resolved upstream URL is the
// catalog entry's server URL. A templated catalog URL is filled with the same
// values that produced the row URL. Comparison is SameCanonicalResource, so a
// trailing slash or default port does not hide a match. An empty catalog URL,
// or a template that these values cannot fill, does not match.
func catalogServerMatches(entry catalogdomain.MCPServer, res upstreamResolution) bool {
	if !res.ready {
		return false
	}
	catalogURL, ok := resolveCatalogServerURL(entry, res.values)
	if !ok {
		return false
	}
	return registrydomain.SameCanonicalResource(res.url, catalogURL)
}

// catalogOptionURLMatches reports whether resolved equals the catalog template
// filled with one combination of its closed option values. A variable without
// options cannot be guessed. A product of options above catalogOptionExpansionCap
// is not expanded.
func catalogOptionURLMatches(entry catalogdomain.MCPServer, resolved string) bool {
	raw := strings.TrimSpace(entry.URL)
	if raw == "" || resolved == "" || !strings.Contains(raw, "{") {
		return false
	}
	names := registrydomain.TemplateVariableNames(raw)
	if len(names) == 0 {
		return false
	}
	byName := make(map[string]catalogdomain.MCPURLVariable, len(entry.URLVariables))
	vars := make([]registrydomain.MCPURLVariable, 0, len(entry.URLVariables))
	for _, v := range entry.URLVariables {
		byName[v.Name] = v
		vars = append(vars, toRegistryURLVar(v))
	}
	options := make([][]string, len(names))
	count := 1
	for i, name := range names {
		variable, ok := byName[name]
		if !ok {
			return false
		}
		for _, option := range variable.Options {
			value := strings.TrimSpace(option.Value)
			if value != "" {
				options[i] = append(options[i], value)
			}
		}
		if len(options[i]) == 0 {
			return false
		}
		count *= len(options[i])
		if count > catalogOptionExpansionCap {
			return false
		}
	}
	values := make(map[string]string, len(names))
	var walk func(int) bool
	walk = func(i int) bool {
		if i == len(names) {
			expanded, err := registrydomain.ResolveURL(raw, vars, values)
			return err == nil && registrydomain.SameCanonicalResource(resolved, expanded)
		}
		for _, value := range options[i] {
			values[names[i]] = value
			if walk(i + 1) {
				return true
			}
		}
		return false
	}
	return walk(0)
}

func resolveCatalogServerURL(entry catalogdomain.MCPServer, values map[string]string) (string, bool) {
	raw := strings.TrimSpace(entry.URL)
	if raw == "" {
		return "", false
	}
	if !strings.Contains(raw, "{") {
		return raw, true
	}
	vars := make([]registrydomain.MCPURLVariable, 0, len(entry.URLVariables))
	for _, v := range entry.URLVariables {
		vars = append(vars, toRegistryURLVar(v))
	}
	resolved, err := registrydomain.ResolveURL(raw, vars, values)
	if err != nil {
		return "", false
	}
	return resolved, true
}

func autoAuth(cfg *registrydomain.MCPAuth, meta *UpstreamAuthServer, client *RegisteredClient) *registrydomain.MCPAuth {
	out := *cfg
	out.ClientID = client.ClientID
	out.ClientSecret = client.ClientSecret
	out.AuthorizeURL = meta.AuthorizationEndpoint
	out.TokenURL = meta.TokenEndpoint
	out.UserinfoURL = meta.UserinfoEndpoint
	if len(out.Scopes) == 0 {
		out.Scopes = meta.ScopesSupported
	}
	if out.Resource == "" {
		out.Resource = meta.Resource
	}
	return &out
}

func manualAuth(cfg *registrydomain.MCPAuth, meta *UpstreamAuthServer) *registrydomain.MCPAuth {
	out := *cfg
	out.AuthorizeURL = meta.AuthorizationEndpoint
	out.TokenURL = meta.TokenEndpoint
	out.UserinfoURL = meta.UserinfoEndpoint
	if len(out.Scopes) == 0 {
		out.Scopes = meta.ScopesSupported
	}
	if out.Resource == "" {
		out.Resource = meta.Resource
	}
	return &out
}

// clientKey is the legacy cache key: the gateway plus the credential fingerprint
// (registrydomain.ForwardedVaultProvider), never the registry id.
//
// A refresh token can only be redeemed by the client it was issued to. Keyed by
// registry, two instances of one catalog code — the same provider, so one shared
// credential — each registered their own client, and whichever instance a call
// arrived through refreshed the other's token with the wrong client_id: the
// upstream answered invalid_grant and the user was told their session had
// expired while the connect page still said connected.
//
// The fingerprint is the URL template as written, so two principals who resolve
// it to different hosts would share one client. clientCacheKey adds the
// authorization server. Rows already stored under clientKey stay readable for
// the server they were registered with.
func clientKey(gatewayID ids.GatewayID, reg *registrydomain.Registry) string {
	return gatewayID.String() + "|" + registrydomain.ForwardedVaultProvider(reg)
}

func clientCacheKey(gatewayID ids.GatewayID, reg *registrydomain.Registry, meta *UpstreamAuthServer) string {
	return clientKey(gatewayID, reg) + "|" + authorizationServerID(meta)
}

func authorizationServerID(meta *UpstreamAuthServer) string {
	sum := sha256.Sum256([]byte(ValidatedIssuer(meta)))
	return hex.EncodeToString(sum[:])
}

// NormalizeIssuerURL is the issuer identifier form used for RFC 8414 comparison
// and for the dynamic-client cache key: lowercase scheme and host, default port
// removed, trailing slash removed. An unparseable value returns "".
func NormalizeIssuerURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" {
		return ""
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https", "http":
	default:
		return ""
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	if port := parsed.Port(); port != "" {
		defaultPort := (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80")
		if !defaultPort {
			host = host + ":" + port
		}
	}
	parsed.Host = host
	parsed.Fragment = ""
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return parsed.String()
}

// IssuerMatchesAuthorizationServer reports whether the issuer a metadata
// document declared is the authorization server URL that document was fetched
// for (RFC 8414 §3.3). Comparison uses NormalizeIssuerURL.
func IssuerMatchesAuthorizationServer(claimed, fetched string) bool {
	want := NormalizeIssuerURL(fetched)
	return want != "" && NormalizeIssuerURL(claimed) == want
}

// ValidatedIssuer is the authorization-server URL Discover accepted. It is the
// fetched URL, not the issuer string the document claimed. Empty when Discover
// has not accepted the server.
func ValidatedIssuer(meta *UpstreamAuthServer) string {
	if meta == nil {
		return ""
	}
	return NormalizeIssuerURL(meta.ValidatedIssuer)
}

// ClientSlot is the cache key a dynamic client is read and written under.
// A live client on the validated-server key wins. A row still stored under the
// legacy key is used when it was registered for this server. A row that records
// no server is used only for a fixed-host registry; a templated host registers
// its own client instead of sharing that row.
func (s *connectService) ClientSlot(ctx context.Context, gatewayID ids.GatewayID, reg *registrydomain.Registry, meta *UpstreamAuthServer) (string, error) {
	if ValidatedIssuer(meta) == "" {
		return "", fmt.Errorf("oauth dcr: authorization server was not validated")
	}
	scoped := clientCacheKey(gatewayID, reg, meta)
	client, err := s.registrar.CachedClient(ctx, scoped)
	if err != nil || client != nil {
		return scoped, err
	}
	legacy := clientKey(gatewayID, reg)
	old, err := s.registrar.CachedClient(ctx, legacy)
	if err != nil {
		return scoped, err
	}
	if legacyRegistrationFor(old, meta, reg) {
		return legacy, nil
	}
	return scoped, nil
}

// legacyRegistrationFor reports whether a client stored under the legacy key
// belongs to this authorization server. An issuer left empty was stored before
// the binding existed. That row stays readable for a fixed host. A templated
// host does not reuse it: the template resolves to more than one server.
func legacyRegistrationFor(cached *RegisteredClient, meta *UpstreamAuthServer, reg *registrydomain.Registry) bool {
	if cached == nil || meta == nil {
		return false
	}
	if cached.Issuer == "" {
		if reg != nil && reg.MCPTarget != nil && reg.MCPTarget.HasURLVariables() {
			return false
		}
	} else if NormalizeIssuerURL(cached.Issuer) != ValidatedIssuer(meta) {
		return false
	}
	if cached.RegistrationEndpoint != "" && cached.RegistrationEndpoint != meta.RegistrationEndpoint {
		return false
	}
	return true
}

// DropRegisteredClient marks the cached dynamic client the token endpoint
// rejected unusable, when that client_id is still the one stored under slot.
// slot is the ClientSlot key the failing exchange or refresh already used.
// The install values are not read again: a later read can name another
// authorization server, and dropping that server's key would force every user
// of it to reconnect (ENG-2241). A row for a different client is left alone.
func (s *connectService) DropRegisteredClient(ctx context.Context, gatewayID ids.GatewayID, reg *registrydomain.Registry, clientID, slot string) error {
	if s == nil || s.registrar == nil || reg == nil || clientID == "" || slot == "" {
		return nil
	}
	return s.registrar.DropCachedClient(ctx, slot, clientID)
}

// CredentialUsable reports whether a credential stored for this registry can
// still be redeemed — everything the refresh needs beyond the credential
// itself.
//
// For a dynamically registered client that means the registration: the refresh
// token was issued to it and cannot be redeemed without it, and it lives in the
// shared cache while the credential lives in the vault, so the credential
// outlives it whenever that cache is lost. Until this was checked, the Portal
// and the connect page read the vault alone and called such an account
// connected while every tool call was refused with "user consent required".
//
// A registry whose client is configured (not registered on the fly) has nothing
// that can go missing here, and neither has one that forwards no credential.
// A lookup that fails answers "usable": a cache blip must not tell every user
// to reconnect.
func (s *connectService) CredentialUsable(
	ctx context.Context,
	gatewayID ids.GatewayID,
	reg *registrydomain.Registry,
) (bool, error) {
	return s.credentialUsable(ctx, gatewayID, principalFromContext(ctx), reg)
}

func (s *connectService) credentialUsable(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	reg *registrydomain.Registry,
) (bool, error) {
	cfg := forwardedAuth(reg)
	if cfg == nil || cfg.Registration != registrydomain.RegistrationAuto || s.registrar == nil {
		return true, nil
	}
	meta, err := s.discover(ctx, gatewayID, principalSub, reg, upstreamResolution{})
	if err != nil {
		return true, err
	}
	slot, err := s.ClientSlot(ctx, gatewayID, reg, meta)
	if err != nil {
		return true, err
	}
	client, err := s.registrar.CachedClient(ctx, slot)
	if err != nil {
		return true, err
	}
	return client != nil, nil
}

func principalFromContext(ctx context.Context) string {
	if p := identity.PrincipalFromContext(ctx); p != nil {
		return p.Subject
	}
	return ""
}
