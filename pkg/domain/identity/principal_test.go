package identity

import "testing"

func TestHasScopes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		held     []string
		required []string
		want     bool
	}{
		{"no requirements", nil, nil, true},
		{"exact match", []string{"mcp:use"}, []string{"mcp:use"}, true},
		{"missing", []string{"openid"}, []string{"mcp:use"}, false},
		{"entra leaf satisfies resource-qualified requirement", []string{"mcp.access"}, []string{"api://client-id/mcp.access"}, true},
		{"exact resource-qualified match", []string{"api://client-id/mcp.access"}, []string{"api://client-id/mcp.access"}, true},
		{"leaf mismatch", []string{"other.scope"}, []string{"api://client-id/mcp.access"}, false},
		{"trailing slash requirement is not satisfied by empty leaf", []string{""}, []string{"api://client-id/"}, false},
		{"offline_access is request-only, not enforced", []string{"mcp.access"}, []string{"mcp.access", "offline_access"}, true},
		{"protocol scopes alone always pass", nil, []string{"openid", "profile", "email", "offline_access"}, true},
		{"protocol scopes do not mask a missing resource scope", []string{"openid"}, []string{"offline_access", "mcp.access"}, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := &Principal{Scopes: tt.held}
			if got := p.HasScopes(tt.required); got != tt.want {
				t.Fatalf("HasScopes(%v) with %v = %v, want %v", tt.required, tt.held, got, tt.want)
			}
		})
	}
}
