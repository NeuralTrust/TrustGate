package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalidToken = errors.New("oidc: invalid token")

const clockSkew = 60 * time.Second

var defaultAlgorithms = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
	"EdDSA",
}

type Validator struct {
	jwks      *JWKSCache
	discovery *discovery
}

func NewValidator(client *http.Client) *Validator {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Validator{jwks: NewJWKSCache(client), discovery: newDiscovery(client)}
}

func (v *Validator) Validate(ctx context.Context, raw string, cfg *authdomain.OAuth2Config) (*identity.Principal, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: no oauth2 config", ErrInvalidToken)
	}
	algorithms := cfg.Algorithms
	if len(algorithms) == 0 {
		algorithms = defaultAlgorithms
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods(algorithms),
		jwt.WithLeeway(clockSkew),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
	)
	claims := jwt.MapClaims{}
	token, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		jwksURL := cfg.JWKSURL
		if jwksURL == "" {
			var derr error
			jwksURL, derr = v.discovery.jwksURI(ctx, cfg.Issuer)
			if derr != nil {
				return nil, derr
			}
		}
		return v.jwks.Key(ctx, jwksURL, kid)
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	iss, _ := claims.GetIssuer()
	if iss != cfg.Issuer {
		return nil, fmt.Errorf("%w: issuer %q not trusted", ErrInvalidToken, iss)
	}
	if len(cfg.Audiences) > 0 {
		aud, _ := claims.GetAudience()
		if !identity.AudienceMatches(aud, cfg.Audiences) {
			return nil, fmt.Errorf("%w: audience mismatch", ErrInvalidToken)
		}
	}

	scopes := extractScopes(claims)
	principal := &identity.Principal{
		Subject:  subjectOf(claims),
		Method:   identity.MethodJWT,
		Issuer:   iss,
		Claims:   claims,
		Scopes:   scopes,
		RawToken: raw,
	}
	if !principal.HasScopes(cfg.RequiredScopes) {
		return nil, fmt.Errorf("%w: missing required scopes", ErrInvalidToken)
	}
	return principal, nil
}

func subjectOf(claims jwt.MapClaims) string {
	if oid, ok := claims["oid"].(string); ok && oid != "" {
		return oid
	}
	sub, _ := claims.GetSubject()
	return sub
}

func extractScopes(claims jwt.MapClaims) []string {
	var out []string
	switch scp := claims["scp"].(type) {
	case string:
		out = append(out, strings.Fields(scp)...)
	case []any:
		for _, s := range scp {
			if str, ok := s.(string); ok {
				out = append(out, str)
			}
		}
	}
	if scope, ok := claims["scope"].(string); ok {
		out = append(out, strings.Fields(scope)...)
	}
	for _, claim := range []string{"permissions", "roles"} {
		if vals, ok := claims[claim].([]any); ok {
			for _, p := range vals {
				if str, ok := p.(string); ok {
					out = append(out, str)
				}
			}
		}
	}
	return dedupe(out)
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
