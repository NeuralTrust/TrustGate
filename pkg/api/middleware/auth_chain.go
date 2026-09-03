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

package middleware

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

const headerXFCC = "X-Forwarded-Client-Cert"

type chainIdentityResolver struct {
	apiKeys           appauth.APIKeyFinder
	credentials       appauth.CredentialFinder
	paths             appconsumer.PathResolver
	jwt               appauth.JWTValidator
	intro             appauth.IntrospectionValidator
	mtls              appauth.MTLSValidator
	certs             appauth.ClientCertificateExtractor
	session           appauth.SessionTokenVerifier
	xfccPeers         []*net.IPNet
	defaultIdPEnabled bool
}

func NewChainIdentityResolver(
	apiKeys appauth.APIKeyFinder,
	credentials appauth.CredentialFinder,
	paths appconsumer.PathResolver,
	jwtValidator appauth.JWTValidator,
	introValidator appauth.IntrospectionValidator,
	mtlsValidator appauth.MTLSValidator,
	certExtractor appauth.ClientCertificateExtractor,
	sessionVerifier appauth.SessionTokenVerifier,
	trustXFCCFrom []string,
	defaultIdPEnabled bool,
) IdentityResolver {
	return &chainIdentityResolver{
		apiKeys:           apiKeys,
		credentials:       credentials,
		paths:             paths,
		jwt:               jwtValidator,
		intro:             introValidator,
		mtls:              mtlsValidator,
		certs:             certExtractor,
		session:           sessionVerifier,
		xfccPeers:         parseTrustedPeers(trustXFCCFrom),
		defaultIdPEnabled: defaultIdPEnabled,
	}
}

func parseTrustedPeers(entries []string) []*net.IPNet {
	var out []*net.IPNet
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "/") {
			if ip := net.ParseIP(e); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
				continue
			}
		}
		_, ipnet, err := net.ParseCIDR(e)
		if err != nil {
			slog.Warn("auth chain: ignoring malformed TRUST_XFCC_FROM entry", slog.String("entry", e))
			continue
		}
		out = append(out, ipnet)
	}
	return out
}

type authScope map[ids.AuthID]struct{}

func (s authScope) allows(id ids.AuthID) bool {
	if s == nil {
		return true
	}
	_, ok := s[id]
	return ok
}

func (r *chainIdentityResolver) Resolve(c *fiber.Ctx) (Identity, error) {
	scope, err := r.pathScope(c)
	if err != nil {
		return Identity{}, resolver.ErrUnauthenticated
	}
	if cert := r.clientCertificate(c); cert != nil {
		return r.resolveMTLS(c.UserContext(), cert, scope)
	}
	if token := bearerToken(c); token != "" {
		return r.resolveBearer(c.UserContext(), token, scope)
	}
	if rawKey := c.Get(resolver.HeaderAPIKey); rawKey != "" {
		return r.resolveAPIKey(c.UserContext(), rawKey, scope)
	}
	return Identity{}, resolver.ErrUnauthenticated
}

func (r *chainIdentityResolver) pathScope(c *fiber.Ctx) (authScope, error) {
	if r.paths == nil {
		return nil, nil
	}
	matches, err := r.paths.Match(c.UserContext(), c.Hostname(), c.Path())
	if err != nil {
		slog.Warn("auth chain: path-first lookup failed; rejecting request",
			slog.String("path", c.Path()), slog.String("error", err.Error()))
		return nil, err
	}
	if len(matches) == 0 {
		return nil, nil
	}
	scope := authScope{}
	hasOAuth2 := false
	hasEnabledOAuth2 := false
	hasEnabledAuth := false
	for _, m := range matches {
		for _, a := range m.Auths {
			scope[a.ID] = struct{}{}
			if a.Enabled {
				hasEnabledAuth = true
			}
			if a.Type == authdomain.TypeOAuth2 {
				hasOAuth2 = true
				if a.Enabled {
					hasEnabledOAuth2 = true
				}
			}
		}
	}
	// The built-in provider bootstraps consumers that carry no credential of
	// their own. Once a path has an enabled one — an api key, mTLS, or its own
	// oauth2 IdP — that credential is the only way in: falling back here would
	// let any platform login reach the consumer without it.
	defaultIdPUsable := r.defaultIdPEnabled && !hasOAuth2 && !hasEnabledAuth
	c.Locals(OAuthChallengeAllowedLocal, hasEnabledOAuth2 || defaultIdPUsable)
	if defaultIdPUsable {
		scope[appauth.DefaultIdPAuthID()] = struct{}{}
	}
	return scope, nil
}

func (r *chainIdentityResolver) resolveMTLS(ctx context.Context, cert *x509.Certificate, scope authScope) (Identity, error) {
	candidates, err := r.credentials.MTLSAuths(ctx)
	if err != nil {
		return Identity{}, resolver.ErrUnauthenticated
	}
	for _, a := range candidates {
		if !scope.allows(a.ID) {
			continue
		}
		principal, err := r.mtls.Validate(cert, a.Config.MTLS)
		if err != nil {
			continue
		}
		return Identity{GatewayID: a.GatewayID, AuthID: a.ID, Principal: principal}, nil
	}
	return Identity{}, resolver.ErrUnauthenticated
}

func (r *chainIdentityResolver) resolveBearer(ctx context.Context, token string, scope authScope) (Identity, error) {
	candidates, err := r.credentials.OAuth2Auths(ctx)
	if err != nil {
		return Identity{}, resolver.ErrUnauthenticated
	}
	if isJWT(token) {
		sessIss := ""
		if r.session != nil {
			sessIss = r.session.Issuer()
		}
		if r.session != nil && unverifiedIssuer(token) == sessIss {
			return r.resolveSession(ctx, token, candidates, scope)
		}
		// TEMP DEBUG (store 401): a JWT that isn't routed to the session verifier
		// means its iss doesn't match the gateway signer — it'll be treated as an
		// upstream IdP token and almost certainly rejected.
		slog.Warn("TEMP DEBUG store401: bearer not routed to session verifier",
			slog.String("token_iss", unverifiedIssuer(token)),
			slog.String("session_iss", sessIss),
			slog.Bool("session_nil", r.session == nil))
		return r.resolveJWT(ctx, token, candidates, scope)
	}
	return r.resolveOpaque(ctx, token, candidates, scope)
}

func (r *chainIdentityResolver) resolveSession(ctx context.Context, token string, candidates []*authdomain.Auth, scope authScope) (Identity, error) {
	if scope == nil && r.paths != nil {
		slog.Warn("TEMP DEBUG store401: nil scope for path (no consumer match)")
		return Identity{}, resolver.ErrUnauthenticated
	}
	principal, err := r.session.Verify(ctx, token)
	if err != nil {
		slog.Warn("TEMP DEBUG store401: session.Verify failed", slog.String("error", err.Error()))
		return Identity{}, resolver.ErrUnauthenticated
	}
	if principal.Subject == "" {
		slog.Warn("TEMP DEBUG store401: empty subject")
		return Identity{}, resolver.ErrUnauthenticated
	}
	if use, _ := principal.Claims["token_use"].(string); use != "mcp_session" {
		slog.Warn("TEMP DEBUG store401: token_use not mcp_session", slog.Any("token_use", principal.Claims["token_use"]))
		return Identity{}, resolver.ErrUnauthenticated
	}
	authID, _ := principal.Claims["authid"].(string)
	if authID == "" {
		slog.Warn("TEMP DEBUG store401: empty authid claim")
		return Identity{}, resolver.ErrUnauthenticated
	}
	// TEMP DEBUG (store 401): dump the discriminating claims + scope once.
	scopeIDs := make([]string, 0, len(scope))
	for id := range scope {
		scopeIDs = append(scopeIDs, id.String())
	}
	slog.Warn("TEMP DEBUG store401: session claims",
		slog.String("authid", authID),
		slog.Any("aud", principal.Claims["aud"]),
		slog.Any("scope_claim", principal.Claims["scope"]),
		slog.Any("gwid", principal.Claims["gwid"]),
		slog.Any("org", principal.Claims["org"]),
		slog.Any("path_scope_auth_ids", scopeIDs),
		slog.Int("candidate_count", len(candidates)))
	matchedCandidate := false
	for _, a := range candidates {
		if a.ID.String() != authID || !scope.allows(a.ID) {
			continue
		}
		matchedCandidate = true
		cfg := a.Config.OAuth2
		if cfg == nil {
			slog.Warn("TEMP DEBUG store401: candidate has no oauth2 config", slog.String("authid", a.ID.String()))
			return Identity{}, resolver.ErrUnauthenticated
		}
		if !identity.AudienceMatches(identity.AudiencesFromClaim(principal.Claims["aud"]), cfg.Audiences) {
			slog.Warn("TEMP DEBUG store401: audience mismatch",
				slog.Any("token_aud", principal.Claims["aud"]), slog.Any("cfg_audiences", cfg.Audiences))
			return Identity{}, resolver.ErrUnauthenticated
		}
		if !principal.HasScopes(cfg.RequiredScopes) {
			slog.Warn("TEMP DEBUG store401: required scopes not met",
				slog.Any("token_scope", principal.Claims["scope"]), slog.Any("required_scopes", cfg.RequiredScopes))
			return Identity{}, resolver.ErrUnauthenticated
		}
		gatewayID := a.GatewayID
		if appauth.IsDefaultIdP(a) {
			gw, err := gatewayFromClaim(principal.Claims["gwid"])
			if err != nil {
				slog.Warn("TEMP DEBUG store401: gwid claim unusable", slog.Any("gwid", principal.Claims["gwid"]))
				return Identity{}, resolver.ErrUnauthenticated
			}
			gatewayID = gw
		}
		return Identity{GatewayID: gatewayID, AuthID: a.ID, Principal: principal}, nil
	}
	if !matchedCandidate {
		slog.Warn("TEMP DEBUG store401: no candidate matched authid within path scope",
			slog.String("authid", authID))
	}
	return Identity{}, resolver.ErrUnauthenticated
}

func gatewayFromClaim(v any) (ids.GatewayID, error) {
	raw, _ := v.(string)
	if raw == "" {
		return ids.GatewayID{}, resolver.ErrUnauthenticated
	}
	return ids.Parse[ids.GatewayKind](raw)
}

func (r *chainIdentityResolver) resolveJWT(ctx context.Context, token string, candidates []*authdomain.Auth, scope authScope) (Identity, error) {
	if scope == nil && r.paths != nil {
		return Identity{}, resolver.ErrUnauthenticated
	}
	issuer := unverifiedIssuer(token)
	for _, a := range candidates {
		cfg := a.Config.OAuth2
		if cfg == nil || cfg.Issuer != issuer || !scope.allows(a.ID) {
			continue
		}
		var principal *identity.Principal
		var err error
		if cfg.JWKSURL != "" || cfg.IntrospectionURL == "" {
			principal, err = r.jwt.Validate(ctx, token, cfg)
		} else {
			principal, err = r.intro.Validate(ctx, token, cfg)
		}
		if err != nil {
			continue
		}
		return Identity{GatewayID: a.GatewayID, AuthID: a.ID, Principal: principal}, nil
	}
	return Identity{}, resolver.ErrUnauthenticated
}

func (r *chainIdentityResolver) resolveOpaque(ctx context.Context, token string, candidates []*authdomain.Auth, scope authScope) (Identity, error) {
	if scope == nil && r.paths != nil {
		return Identity{}, resolver.ErrUnauthenticated
	}
	for _, a := range candidates {
		cfg := a.Config.OAuth2
		if cfg == nil || cfg.IntrospectionURL == "" || !scope.allows(a.ID) {
			continue
		}
		principal, err := r.intro.Validate(ctx, token, cfg)
		if err != nil {
			continue
		}
		return Identity{GatewayID: a.GatewayID, AuthID: a.ID, Principal: principal}, nil
	}
	return Identity{}, resolver.ErrUnauthenticated
}

func (r *chainIdentityResolver) resolveAPIKey(ctx context.Context, rawKey string, scope authScope) (Identity, error) {
	a, err := r.apiKeys.FindByAPIKey(ctx, rawKey)
	if err != nil || a == nil || !a.Enabled || a.Type != authdomain.TypeAPIKey {
		return Identity{}, resolver.ErrUnauthenticated
	}
	if !scope.allows(a.ID) {
		return Identity{}, resolver.ErrUnauthenticated
	}
	principal := &identity.Principal{
		Subject: a.Name,
		Method:  identity.MethodAPIKey,
	}
	return Identity{GatewayID: a.GatewayID, AuthID: a.ID, Principal: principal}, nil
}

func (r *chainIdentityResolver) clientCertificate(c *fiber.Ctx) *x509.Certificate {
	if state := c.Context().TLSConnectionState(); state != nil && len(state.PeerCertificates) > 0 {
		return state.PeerCertificates[0]
	}
	if r.certs == nil || !r.trustsXFCCPeer(c) {
		return nil
	}
	if xfcc := c.Get(headerXFCC); xfcc != "" {
		cert, err := r.certs.FromXFCC(xfcc)
		if err != nil {
			return nil
		}
		return cert
	}
	return nil
}

func (r *chainIdentityResolver) trustsXFCCPeer(c *fiber.Ctx) bool {
	if len(r.xfccPeers) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(c.Context().RemoteAddr().String())
	if err != nil {
		host = c.Context().RemoteAddr().String()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range r.xfccPeers {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func bearerToken(c *fiber.Ctx) string {
	header := c.Get(fiber.HeaderAuthorization)
	if header == "" {
		return ""
	}
	token, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(token)
}

func isJWT(token string) bool {
	return strings.Count(token, ".") == 2
}

func unverifiedIssuer(token string) string {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		return ""
	}
	iss, _ := claims.GetIssuer()
	return iss
}
