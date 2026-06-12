package identity

import "strings"

// AudienceMatches reports whether any presented audience matches any
// expected one. An "api://" resource URI and its bare identifier are
// treated as equivalent: Entra advertises the resource as api://{client_id}
// but v2.0 access tokens carry the bare GUID in aud (the URI form is v1.0
// behavior). This is the single audience-matching rule for every inbound
// mechanism (JWT, introspection) and for downstream passthrough guards.
func AudienceMatches(have, want []string) bool {
	for _, h := range have {
		for _, w := range want {
			if h == w || h == strings.TrimPrefix(w, "api://") || w == strings.TrimPrefix(h, "api://") {
				return true
			}
		}
	}
	return false
}

// AudiencesFromClaim normalizes an aud claim, which RFC 7519/7662 allow to
// be a single string or an array.
func AudiencesFromClaim(aud any) []string {
	switch a := aud.(type) {
	case string:
		if a == "" {
			return nil
		}
		return []string{a}
	case []string:
		return a
	case []any:
		out := make([]string, 0, len(a))
		for _, item := range a {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// HasAudience checks the principal's aud claim against one expected audience.
func (p *Principal) HasAudience(expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return false
	}
	return AudienceMatches(AudiencesFromClaim(p.Claims["aud"]), []string{expected})
}
