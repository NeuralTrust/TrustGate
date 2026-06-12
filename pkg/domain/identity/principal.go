package identity

import (
	"context"
	"strings"
)

type Method string

const (
	MethodAPIKey        Method = "api_key"
	MethodJWT           Method = "jwt"
	MethodIntrospection Method = "introspection"
	MethodMTLS          Method = "mtls"
)

type Principal struct {
	Subject  string         `json:"subject"`
	Method   Method         `json:"method"`
	Issuer   string         `json:"issuer,omitempty"`
	Claims   map[string]any `json:"claims,omitempty"`
	Scopes   []string       `json:"scopes,omitempty"`
	RawToken string         `json:"-"`
}

var protocolScopes = map[string]struct{}{
	"openid":         {},
	"profile":        {},
	"email":          {},
	"offline_access": {},
}

// IsProtocolScope reports whether the scope is an OIDC protocol scope that
// access tokens do not carry; configs must not require them.
func IsProtocolScope(scope string) bool {
	_, ok := protocolScopes[scope]
	return ok
}

func (p *Principal) HasScopes(required []string) bool {
	if len(required) == 0 {
		return true
	}
	if p == nil {
		return false
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
		if leaf, found := resourceURILeaf(r); found {
			if _, ok := held[leaf]; ok {
				continue
			}
		}
		return false
	}
	return true
}

// resourceURILeaf extracts the bare scope name from an "api://" resource URI
// (Entra emits the leaf alone in the scp claim of v2 access tokens). The
// fallback is deliberately restricted to that prefix: a generic held scope
// must not satisfy arbitrary namespaced requirements like "tenant/admin".
func resourceURILeaf(scope string) (string, bool) {
	if !strings.HasPrefix(scope, "api://") {
		return "", false
	}
	idx := strings.LastIndex(scope, "/")
	if idx < 0 || idx == len(scope)-1 {
		return "", false
	}
	return scope[idx+1:], true
}

type contextKey struct{}

func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, contextKey{}, p)
}

func PrincipalFromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(contextKey{}).(*Principal)
	return p
}
