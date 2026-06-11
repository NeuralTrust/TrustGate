// Package identity describes the authenticated subject (Principal) produced
// by inbound credential validation, independent of the credential mechanism.
package identity

import (
	"context"
	"strings"
)

// Method is the credential mechanism that authenticated the Principal.
type Method string

const (
	MethodAPIKey        Method = "api_key"
	MethodJWT           Method = "jwt"
	MethodIntrospection Method = "introspection"
	MethodMTLS          Method = "mtls"
)

// Principal is the authenticated subject attached to the request context.
// RawToken is retained for downstream On-Behalf-Of / token exchange (Phase 4)
// and must never be serialized.
type Principal struct {
	Subject  string         `json:"subject"`
	Method   Method         `json:"method"`
	Issuer   string         `json:"issuer,omitempty"`
	Claims   map[string]any `json:"claims,omitempty"`
	Scopes   []string       `json:"scopes,omitempty"`
	RawToken string         `json:"-"`
}

// protocolScopes are OIDC/OAuth grant-level scopes: they shape what the
// authorization server issues (ID token claims, refresh token) but are never
// echoed into a resource access token's scp claim, so a resource server must
// not enforce them.
var protocolScopes = map[string]struct{}{
	"openid":         {},
	"profile":        {},
	"email":          {},
	"offline_access": {},
}

// HasScopes reports whether the principal holds every required scope. A
// resource-qualified requirement (e.g. Entra's "api://{client}/mcp.access",
// as advertised in scopes_supported and requested by OAuth clients) is also
// satisfied by its bare leaf name ("mcp.access"), because Entra strips the
// resource prefix from the scp/roles claims it issues. OIDC protocol scopes
// (openid, profile, email, offline_access) are request-time directives to the
// authorization server and are skipped here.
func (p *Principal) HasScopes(required []string) bool {
	if len(required) == 0 {
		return true
	}
	held := make(map[string]struct{}, len(p.Scopes))
	for _, s := range p.Scopes {
		held[s] = struct{}{}
	}
	for _, r := range required {
		if _, ok := protocolScopes[r]; ok {
			continue
		}
		if _, ok := held[r]; ok {
			continue
		}
		if leaf, found := lastSegment(r); found {
			if _, ok := held[leaf]; ok {
				continue
			}
		}
		return false
	}
	return true
}

func lastSegment(scope string) (string, bool) {
	idx := strings.LastIndex(scope, "/")
	if idx < 0 || idx == len(scope)-1 {
		return "", false
	}
	return scope[idx+1:], true
}

type contextKey struct{}

// WithPrincipal attaches the principal to the context.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, contextKey{}, p)
}

// PrincipalFromContext returns the authenticated principal, or nil when the
// request was not authenticated through the credential chain.
func PrincipalFromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(contextKey{}).(*Principal)
	return p
}
