package middleware

import (
	"context"
	"crypto/x509"
	"log/slog"
	"strings"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// headerXFCC is the de-facto header edge proxies use to forward the client
// certificate after terminating TLS.
const headerXFCC = "X-Forwarded-Client-Cert"

// chainIdentityResolver runs the credential chain in fixed precedence:
// mTLS -> JWT -> introspection -> API key. Anti-downgrade: a credential that
// is present but invalid fails the request immediately; there is no silent
// fall-through to a weaker mechanism.
//
// Resolution is path-first: when the request path maps to one or more
// consumers, only the Auth entries attached to those consumers are candidate
// validators. This keeps tenants sharing an IdP (same issuer, even same
// audience) isolated — a token can only authenticate against the gateway
// whose consumer is being addressed.
type chainIdentityResolver struct {
	apiKeys     appauth.APIKeyFinder
	credentials appauth.CredentialFinder
	paths       appconsumer.PathResolver
	jwt         appauth.JWTValidator
	intro       appauth.IntrospectionValidator
	mtls        appauth.MTLSValidator
	certs       appauth.ClientCertificateExtractor
}

func NewChainIdentityResolver(
	apiKeys appauth.APIKeyFinder,
	credentials appauth.CredentialFinder,
	paths appconsumer.PathResolver,
	jwtValidator appauth.JWTValidator,
	introValidator appauth.IntrospectionValidator,
	mtlsValidator appauth.MTLSValidator,
	certExtractor appauth.ClientCertificateExtractor,
) IdentityResolver {
	return &chainIdentityResolver{
		apiKeys:     apiKeys,
		credentials: credentials,
		paths:       paths,
		jwt:         jwtValidator,
		intro:       introValidator,
		mtls:        mtlsValidator,
		certs:       certExtractor,
	}
}

// authScope is the set of Auth IDs attached to the consumers matching the
// request path. nil means unrestricted (no consumer claims the path, or no
// path resolver is wired); an empty scope rejects every credential.
type authScope map[ids.AuthID]struct{}

func (s authScope) allows(id ids.AuthID) bool {
	if s == nil {
		return true
	}
	_, ok := s[id]
	return ok
}

func (r *chainIdentityResolver) Resolve(c *fiber.Ctx) (Identity, error) {
	scope := r.pathScope(c)
	if cert := r.clientCertificate(c); cert != nil {
		return r.resolveMTLS(c.UserContext(), cert, scope)
	}
	if token := bearerToken(c); token != "" {
		return r.resolveBearer(c.UserContext(), token, scope)
	}
	if rawKey := c.Get(HeaderAPIKey); rawKey != "" {
		return r.resolveAPIKey(c.UserContext(), rawKey, scope)
	}
	return Identity{}, ErrUnauthenticated
}

// pathScope resolves the request path to the attached Auth entries of the
// matching consumers. Lookup failures fall back to unrestricted resolution
// (availability over strictness); the per-consumer attachment check in the
// handlers still applies.
func (r *chainIdentityResolver) pathScope(c *fiber.Ctx) authScope {
	if r.paths == nil {
		return nil
	}
	matches, err := r.paths.Match(c.UserContext(), c.Hostname(), c.Path())
	if err != nil {
		slog.Warn("auth chain: path-first lookup failed; resolving unrestricted",
			slog.String("path", c.Path()), slog.String("error", err.Error()))
		return nil
	}
	if len(matches) == 0 {
		return nil
	}
	scope := authScope{}
	for _, m := range matches {
		for _, a := range m.Auths {
			scope[a.ID] = struct{}{}
		}
	}
	return scope
}

func (r *chainIdentityResolver) resolveMTLS(ctx context.Context, cert *x509.Certificate, scope authScope) (Identity, error) {
	candidates, err := r.credentials.MTLSAuths(ctx)
	if err != nil {
		return Identity{}, ErrUnauthenticated
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
	return Identity{}, ErrUnauthenticated
}

func (r *chainIdentityResolver) resolveBearer(ctx context.Context, token string, scope authScope) (Identity, error) {
	candidates, err := r.credentials.OAuth2Auths(ctx)
	if err != nil {
		return Identity{}, ErrUnauthenticated
	}
	if isJWT(token) {
		return r.resolveJWT(ctx, token, candidates, scope)
	}
	return r.resolveOpaque(ctx, token, candidates, scope)
}

func (r *chainIdentityResolver) resolveJWT(ctx context.Context, token string, candidates []*authdomain.Auth, scope authScope) (Identity, error) {
	issuer := unverifiedIssuer(token)
	for _, a := range candidates {
		cfg := a.Config.OAuth2
		if cfg == nil || cfg.Issuer != issuer || !scope.allows(a.ID) {
			continue
		}
		var principal *identity.Principal
		var err error
		// JWKS when available (configured or discoverable); otherwise the
		// entry is introspection-only and the JWT is treated as a reference
		// token at the IdP.
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
	return Identity{}, ErrUnauthenticated
}

func (r *chainIdentityResolver) resolveOpaque(ctx context.Context, token string, candidates []*authdomain.Auth, scope authScope) (Identity, error) {
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
	return Identity{}, ErrUnauthenticated
}

func (r *chainIdentityResolver) resolveAPIKey(ctx context.Context, rawKey string, scope authScope) (Identity, error) {
	a, err := r.apiKeys.FindByAPIKey(ctx, rawKey)
	if err != nil || a == nil || !a.Enabled || a.Type != authdomain.TypeAPIKey {
		return Identity{}, ErrUnauthenticated
	}
	if !scope.allows(a.ID) {
		return Identity{}, ErrUnauthenticated
	}
	principal := &identity.Principal{
		Subject: a.Name,
		Method:  identity.MethodAPIKey,
	}
	return Identity{GatewayID: a.GatewayID, AuthID: a.ID, Principal: principal}, nil
}

// clientCertificate returns the client certificate from the TLS connection
// state (direct termination) or the X-Forwarded-Client-Cert header (edge
// termination). Returns nil when no certificate was presented.
func (r *chainIdentityResolver) clientCertificate(c *fiber.Ctx) *x509.Certificate {
	if state := c.Context().TLSConnectionState(); state != nil && len(state.PeerCertificates) > 0 {
		return state.PeerCertificates[0]
	}
	if r.certs == nil {
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

// unverifiedIssuer reads the iss claim without verifying the signature, only
// to select candidate Auth entries; full validation happens afterwards.
func unverifiedIssuer(token string) string {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		return ""
	}
	iss, _ := claims.GetIssuer()
	return iss
}
