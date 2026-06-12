package middleware

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net"
	"strings"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

const headerXFCC = "X-Forwarded-Client-Cert"

type chainIdentityResolver struct {
	apiKeys     appauth.APIKeyFinder
	credentials appauth.CredentialFinder
	paths       appconsumer.PathResolver
	jwt         appauth.JWTValidator
	intro       appauth.IntrospectionValidator
	mtls        appauth.MTLSValidator
	certs       appauth.ClientCertificateExtractor
	xfccPeers   []*net.IPNet
}

func NewChainIdentityResolver(
	apiKeys appauth.APIKeyFinder,
	credentials appauth.CredentialFinder,
	paths appconsumer.PathResolver,
	jwtValidator appauth.JWTValidator,
	introValidator appauth.IntrospectionValidator,
	mtlsValidator appauth.MTLSValidator,
	certExtractor appauth.ClientCertificateExtractor,
	trustXFCCFrom []string,
) IdentityResolver {
	return &chainIdentityResolver{
		apiKeys:     apiKeys,
		credentials: credentials,
		paths:       paths,
		jwt:         jwtValidator,
		intro:       introValidator,
		mtls:        mtlsValidator,
		certs:       certExtractor,
		xfccPeers:   parseTrustedPeers(trustXFCCFrom),
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
		return Identity{}, ErrUnauthenticated
	}
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
	for _, m := range matches {
		for _, a := range m.Auths {
			scope[a.ID] = struct{}{}
		}
	}
	return scope, nil
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
	if scope == nil && r.paths != nil {
		return Identity{}, ErrUnauthenticated
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
