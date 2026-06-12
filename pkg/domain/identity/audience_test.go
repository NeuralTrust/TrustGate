package identity

import "testing"

func TestAudienceMatches(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		have []string
		want []string
		ok   bool
	}{
		{"exact match", []string{"https://gw/mcp"}, []string{"https://gw/mcp"}, true},
		{"no match", []string{"other"}, []string{"https://gw/mcp"}, false},
		{"entra uri vs bare guid", []string{"1111-2222"}, []string{"api://1111-2222"}, true},
		{"bare guid configured, uri presented", []string{"api://1111-2222"}, []string{"1111-2222"}, true},
		{"empty have", nil, []string{"x"}, false},
		{"empty want", []string{"x"}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := AudienceMatches(tc.have, tc.want); got != tc.ok {
				t.Fatalf("AudienceMatches(%v, %v) = %v, want %v", tc.have, tc.want, got, tc.ok)
			}
		})
	}
}

func TestAudiencesFromClaim(t *testing.T) {
	t.Parallel()
	if got := AudiencesFromClaim("a"); len(got) != 1 || got[0] != "a" {
		t.Fatalf("string claim = %v", got)
	}
	if got := AudiencesFromClaim([]any{"a", 3, "b"}); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("[]any claim = %v", got)
	}
	if got := AudiencesFromClaim([]string{"a", "b"}); len(got) != 2 {
		t.Fatalf("[]string claim = %v", got)
	}
	if got := AudiencesFromClaim(nil); got != nil {
		t.Fatalf("nil claim = %v", got)
	}
}

func TestPrincipal_HasAudience(t *testing.T) {
	t.Parallel()
	p := &Principal{Claims: map[string]any{"aud": []any{"https://gw/mcp"}}}
	if !p.HasAudience("https://gw/mcp") {
		t.Fatal("expected audience match")
	}
	if p.HasAudience("") {
		t.Fatal("empty expected audience must not match")
	}
	if p.HasAudience("other") {
		t.Fatal("unexpected match")
	}
}
