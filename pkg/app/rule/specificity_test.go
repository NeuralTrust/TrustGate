package rule

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestSpecificityScore(t *testing.T) {
	tests := []struct {
		name string
		path string
		want int
	}{
		{name: "two static segments", path: "/v1/users", want: 23},
		{name: "static + param", path: "/v1/users/{id}", want: 28},
		{name: "static + wildcard", path: "/v1/*", want: 10},
		{name: "two static + wildcard", path: "/v1/test/*", want: 20},
		{name: "static + param + wildcard", path: "/v1/users/{id}/posts/*", want: 35},
		{name: "root wildcard", path: "/*", want: 0},
		{name: "root path", path: "/", want: 3},
		{name: "three static + param", path: "/v1/test/users/{id}", want: 38},
		{name: "exact single segment", path: "/health", want: 13},
		{name: "deep static path", path: "/a/b/c/d", want: 43},
		{name: "only param", path: "/{id}", want: 8},
		{name: "param + wildcard", path: "/{id}/*", want: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SpecificityScore(tt.path)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBestScore(t *testing.T) {
	tests := []struct {
		name string
		rule types.ForwardingRuleDTO
		want int
	}{
		{
			name: "single path",
			rule: types.ForwardingRuleDTO{Path: "/v1/users/{id}"},
			want: 28,
		},
		{
			name: "multi-path returns max",
			rule: types.ForwardingRuleDTO{
				Path:  "/v1/*",
				Paths: []string{"/v1/*", "/v2/test/*"},
			},
			want: 20,
		},
		{
			name: "multi-path with exact",
			rule: types.ForwardingRuleDTO{
				Path:  "/v1/users",
				Paths: []string{"/v1/users", "/v2/users/{id}"},
			},
			want: 28,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BestScore(tt.rule)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSortBySpecificity(t *testing.T) {
	t.Run("sorts most specific first", func(t *testing.T) {
		rules := []types.ForwardingRuleDTO{
			{ID: "catch-all", Path: "/*"},
			{ID: "v1-wildcard", Path: "/v1/*"},
			{ID: "v1-test-wildcard", Path: "/v1/test/*"},
			{ID: "v1-test-param", Path: "/v1/test/users/{id}"},
			{ID: "v1-exact", Path: "/v1/users"},
		}

		SortBySpecificity(rules)

		assert.Equal(t, "v1-test-param", rules[0].ID)
		assert.Equal(t, "v1-exact", rules[1].ID)
		assert.Equal(t, "v1-test-wildcard", rules[2].ID)
		assert.Equal(t, "v1-wildcard", rules[3].ID)
		assert.Equal(t, "catch-all", rules[4].ID)
	})

	t.Run("stable sort preserves order for equal scores", func(t *testing.T) {
		rules := []types.ForwardingRuleDTO{
			{ID: "first", Path: "/v1/users/*"},
			{ID: "second", Path: "/v1/posts/*"},
			{ID: "third", Path: "/v1/items/*"},
		}

		SortBySpecificity(rules)

		assert.Equal(t, "first", rules[0].ID)
		assert.Equal(t, "second", rules[1].ID)
		assert.Equal(t, "third", rules[2].ID)
	})

	t.Run("empty slice does not panic", func(t *testing.T) {
		var rules []types.ForwardingRuleDTO
		assert.NotPanics(t, func() { SortBySpecificity(rules) })
	})

	t.Run("single element unchanged", func(t *testing.T) {
		rules := []types.ForwardingRuleDTO{
			{ID: "only", Path: "/v1/users"},
		}
		SortBySpecificity(rules)
		assert.Equal(t, "only", rules[0].ID)
	})
}
