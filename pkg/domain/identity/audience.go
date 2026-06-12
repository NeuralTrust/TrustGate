package identity

import "strings"

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

func (p *Principal) HasAudience(expected string) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" || p == nil {
		return false
	}
	return AudienceMatches(AudiencesFromClaim(p.Claims["aud"]), []string{expected})
}
