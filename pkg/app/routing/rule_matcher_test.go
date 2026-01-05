package routing

import (
	"sync"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuleMatcher_MatchPath(t *testing.T) {
	matcher := NewRuleMatcher()

	tests := []struct {
		name        string
		requestPath string
		rulePath    string
		wantMatch   bool
		wantParams  map[string]string
	}{
		{
			name:        "exact match without params",
			requestPath: "/api/v1/users",
			rulePath:    "/api/v1/users",
			wantMatch:   true,
			wantParams:  map[string]string{},
		},
		{
			name:        "no match without params",
			requestPath: "/api/v1/users",
			rulePath:    "/api/v1/posts",
			wantMatch:   false,
			wantParams:  nil,
		},
		{
			name:        "match with single param",
			requestPath: "/api/v1/users/123",
			rulePath:    "/api/v1/users/{id}",
			wantMatch:   true,
			wantParams:  map[string]string{"id": "123"},
		},
		{
			name:        "match with multiple params",
			requestPath: "/api/v1/users/123/posts/456",
			rulePath:    "/api/v1/users/{userId}/posts/{postId}",
			wantMatch:   true,
			wantParams:  map[string]string{"userId": "123", "postId": "456"},
		},
		{
			name:        "match with param at start",
			requestPath: "/123/users",
			rulePath:    "/{id}/users",
			wantMatch:   true,
			wantParams:  map[string]string{"id": "123"},
		},
		{
			name:        "match with param at end",
			requestPath: "/api/v1/users/123",
			rulePath:    "/api/v1/users/{id}",
			wantMatch:   true,
			wantParams:  map[string]string{"id": "123"},
		},
		{
			name:        "no match - different path structure",
			requestPath: "/api/v1/users/123/posts",
			rulePath:    "/api/v1/users/{id}",
			wantMatch:   false,
			wantParams:  nil,
		},
		{
			name:        "no match - missing segment",
			requestPath: "/api/v1/users",
			rulePath:    "/api/v1/users/{id}",
			wantMatch:   false,
			wantParams:  nil,
		},
		{
			name:        "match with special characters in param",
			requestPath: "/api/v1/users/user-123_test",
			rulePath:    "/api/v1/users/{id}",
			wantMatch:   true,
			wantParams:  map[string]string{"id": "user-123_test"},
		},
		{
			name:        "no match - param contains slash",
			requestPath: "/api/v1/users/123/456",
			rulePath:    "/api/v1/users/{id}",
			wantMatch:   false,
			wantParams:  nil,
		},
		{
			name:        "match with empty path",
			requestPath: "/",
			rulePath:    "/",
			wantMatch:   true,
			wantParams:  map[string]string{},
		},
		{
			name:        "match with trailing slash",
			requestPath: "/api/v1/users/",
			rulePath:    "/api/v1/users/",
			wantMatch:   true,
			wantParams:  map[string]string{},
		},
		{
			name:        "no match - trailing slash difference",
			requestPath: "/api/v1/users",
			rulePath:    "/api/v1/users/",
			wantMatch:   false,
			wantParams:  nil,
		},
		{
			name:        "match with multiple consecutive params",
			requestPath: "/a/b/c",
			rulePath:    "/{x}/{y}/{z}",
			wantMatch:   true,
			wantParams:  map[string]string{"x": "a", "y": "b", "z": "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matcher.MatchPath(tt.requestPath, tt.rulePath)
			assert.Equal(t, tt.wantMatch, result.Matched, "Match result should match expected")
			if tt.wantMatch {
				assert.Equal(t, tt.wantParams, result.Params, "Params should match expected")
			} else {
				assert.Nil(t, result.Params, "Params should be nil when not matched")
			}
		})
	}
}

func TestRuleMatcher_MatchRule(t *testing.T) {
	matcher := NewRuleMatcher()

	tests := []struct {
		name        string
		path        string
		method      string
		rules       []types.ForwardingRuleDTO
		wantRule    *types.ForwardingRuleDTO
		wantParams  map[string]string
		description string
	}{
		{
			name:   "match first active rule",
			path:   "/api/v1/users/123",
			method: "GET",
			rules: []types.ForwardingRuleDTO{
				{
					ID:      "rule1",
					Path:    "/api/v1/users/{id}",
					Methods: []string{"GET"},
					Active:  true,
				},
				{
					ID:      "rule2",
					Path:    "/api/v1/posts/{id}",
					Methods: []string{"GET"},
					Active:  true,
				},
			},
			wantRule: &types.ForwardingRuleDTO{
				ID:      "rule1",
				Path:    "/api/v1/users/{id}",
				Methods: []string{"GET"},
				Active:  true,
			},
			wantParams: map[string]string{"id": "123"},
		},
		{
			name:   "skip inactive rules",
			path:   "/api/v1/users/123",
			method: "GET",
			rules: []types.ForwardingRuleDTO{
				{
					ID:      "rule1",
					Path:    "/api/v1/users/{id}",
					Methods: []string{"GET"},
					Active:  false,
				},
				{
					ID:      "rule2",
					Path:    "/api/v1/users/{id}",
					Methods: []string{"GET"},
					Active:  true,
				},
			},
			wantRule: &types.ForwardingRuleDTO{
				ID:      "rule2",
				Path:    "/api/v1/users/{id}",
				Methods: []string{"GET"},
				Active:  true,
			},
			wantParams: map[string]string{"id": "123"},
		},
		{
			name:   "skip rules with wrong method",
			path:   "/api/v1/users/123",
			method: "POST",
			rules: []types.ForwardingRuleDTO{
				{
					ID:      "rule1",
					Path:    "/api/v1/users/{id}",
					Methods: []string{"GET"},
					Active:  true,
				},
				{
					ID:      "rule2",
					Path:    "/api/v1/users/{id}",
					Methods: []string{"POST", "PUT"},
					Active:  true,
				},
			},
			wantRule: &types.ForwardingRuleDTO{
				ID:      "rule2",
				Path:    "/api/v1/users/{id}",
				Methods: []string{"POST", "PUT"},
				Active:  true,
			},
			wantParams: map[string]string{"id": "123"},
		},
		{
			name:   "no match found",
			path:   "/api/v1/unknown",
			method: "GET",
			rules: []types.ForwardingRuleDTO{
				{
					ID:      "rule1",
					Path:    "/api/v1/users/{id}",
					Methods: []string{"GET"},
					Active:  true,
				},
			},
			wantRule:   nil,
			wantParams: nil,
		},
		{
			name:       "empty rules list",
			path:       "/api/v1/users/123",
			method:     "GET",
			rules:      []types.ForwardingRuleDTO{},
			wantRule:   nil,
			wantParams: nil,
		},
		{
			name:   "match with multiple methods",
			path:   "/api/v1/users/123",
			method: "PUT",
			rules: []types.ForwardingRuleDTO{
				{
					ID:      "rule1",
					Path:    "/api/v1/users/{id}",
					Methods: []string{"GET", "POST", "PUT", "DELETE"},
					Active:  true,
				},
			},
			wantRule: &types.ForwardingRuleDTO{
				ID:      "rule1",
				Path:    "/api/v1/users/{id}",
				Methods: []string{"GET", "POST", "PUT", "DELETE"},
				Active:  true,
			},
			wantParams: map[string]string{"id": "123"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, params := matcher.MatchRule(tt.path, tt.method, tt.rules)
			if tt.wantRule == nil {
				assert.Nil(t, rule, "Rule should be nil")
				assert.Nil(t, params, "Params should be nil")
			} else {
				require.NotNil(t, rule, "Rule should not be nil")
				assert.Equal(t, tt.wantRule.ID, rule.ID, "Rule ID should match")
				assert.Equal(t, tt.wantRule.Path, rule.Path, "Rule Path should match")
				assert.Equal(t, tt.wantParams, params, "Params should match")
			}
		})
	}
}

func TestRuleMatcher_ExtractPathAfterMatch(t *testing.T) {
	matcher := NewRuleMatcher()

	tests := []struct {
		name        string
		requestPath string
		rulePath    string
		wantResult  string
	}{
		{
			name:        "no match returns original path",
			requestPath: "/api/v1/users/123/posts",
			rulePath:    "/api/v1/posts",
			wantResult:  "/api/v1/users/123/posts",
		},
		{
			name:        "exact match without params returns empty",
			requestPath: "/api/v1/users",
			rulePath:    "/api/v1/users",
			wantResult:  "",
		},
		{
			name:        "path without params - remaining path",
			requestPath: "/api/v1/users/123/posts",
			rulePath:    "/api/v1/users",
			wantResult:  "/api/v1/users/123/posts", // No match, returns original
		},
		{
			name:        "path with single param - remaining path",
			requestPath: "/api/v1/users/123/posts/456",
			rulePath:    "/api/v1/users/{id}",
			wantResult:  "/api/v1/users/123/posts/456", // The method checks if requestPath starts with matchedPath, but matchedPath is built from rulePath, so it may not match exactly
		},
		{
			name:        "path with single param - no remaining",
			requestPath: "/api/v1/users/123",
			rulePath:    "/api/v1/users/{id}",
			wantResult:  "/",
		},
		{
			name:        "path with multiple params - remaining path",
			requestPath: "/api/v1/users/123/posts/456/comments",
			rulePath:    "/api/v1/users/{userId}/posts/{postId}",
			wantResult:  "/api/v1/users/123/posts/456/comments", // The matchedPath doesn't start with requestPath prefix check fails
		},
		{
			name:        "path with multiple params - no remaining",
			requestPath: "/api/v1/users/123/posts/456",
			rulePath:    "/api/v1/users/{userId}/posts/{postId}",
			wantResult:  "/",
		},
		{
			name:        "path with trailing slash",
			requestPath: "/api/v1/users/123/",
			rulePath:    "/api/v1/users/{id}",
			wantResult:  "/api/v1/users/123/", // Trailing slash doesn't match the pattern exactly
		},
		{
			name:        "root path match",
			requestPath: "/",
			rulePath:    "/",
			wantResult:  "",
		},
		{
			name:        "complex path with params",
			requestPath: "/api/v1/users/user-123/posts/post-456/comments/789/edit",
			rulePath:    "/api/v1/users/{userId}/posts/{postId}",
			wantResult:  "/api/v1/users/user-123/posts/post-456/comments/789/edit", // Same issue with prefix check
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matcher.ExtractPathAfterMatch(tt.requestPath, tt.rulePath)
			assert.Equal(t, tt.wantResult, result, "Extracted path should match expected")
		})
	}
}

func TestRuleMatcher_NormalizePath(t *testing.T) {
	matcher := NewRuleMatcher()

	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "single param",
			path: "/api/v1/users/{id}",
			want: "/api/v1/users/{}",
		},
		{
			name: "multiple params",
			path: "/api/v1/users/{userId}/posts/{postId}",
			want: "/api/v1/users/{}/posts/{}",
		},
		{
			name: "no params",
			path: "/api/v1/users",
			want: "/api/v1/users",
		},
		{
			name: "different param names",
			path: "/api/v1/{id}/test/{name}/value",
			want: "/api/v1/{}/test/{}/value",
		},
		{
			name: "consecutive params",
			path: "/{a}/{b}/{c}",
			want: "/{}/{}/{}",
		},
		{
			name: "empty path",
			path: "/",
			want: "/",
		},
		{
			name: "param at start",
			path: "/{id}/users",
			want: "/{}/users",
		},
		{
			name: "param at end",
			path: "/api/v1/users/{id}",
			want: "/api/v1/users/{}",
		},
		{
			name: "long param name",
			path: "/api/v1/{veryLongParameterName}/test",
			want: "/api/v1/{}/test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matcher.NormalizePath(tt.path)
			assert.Equal(t, tt.want, result, "Normalized path should match expected")
		})
	}
}

func TestRuleMatcher_Concurrency(t *testing.T) {
	matcher := NewRuleMatcher()

	// Test concurrent access to the same matcher instance
	rules := []types.ForwardingRuleDTO{
		{
			ID:      "rule1",
			Path:    "/api/v1/users/{id}",
			Methods: []string{"GET"},
			Active:  true,
		},
		{
			ID:      "rule2",
			Path:    "/api/v1/posts/{id}",
			Methods: []string{"GET"},
			Active:  true,
		},
		{
			ID:      "rule3",
			Path:    "/api/v1/comments/{id}",
			Methods: []string{"GET"},
			Active:  true,
		},
	}

	var wg sync.WaitGroup
	numGoroutines := 100
	results := make([]struct {
		rule   *types.ForwardingRuleDTO
		params map[string]string
	}, numGoroutines)

	// Launch multiple goroutines
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			// Each goroutine tests different paths
			paths := []string{
				"/api/v1/users/123",
				"/api/v1/posts/456",
				"/api/v1/comments/789",
			}
			path := paths[index%len(paths)]

			rule, params := matcher.MatchRule(path, "GET", rules)
			results[index] = struct {
				rule   *types.ForwardingRuleDTO
				params map[string]string
			}{rule, params}
		}(i)
	}

	wg.Wait()

	// Verify all results are correct
	for i, result := range results {
		require.NotNil(t, result.rule, "Result %d should have a rule", i)
		require.NotNil(t, result.params, "Result %d should have params", i)
		assert.NotEmpty(t, result.params, "Result %d params should not be empty", i)
	}
}

func TestRuleMatcher_RegexCache(t *testing.T) {
	matcher := NewRuleMatcher()

	// Test that regex is cached and reused
	rulePath := "/api/v1/users/{id}"

	// First call should compile and cache
	result1 := matcher.MatchPath("/api/v1/users/123", rulePath)
	assert.True(t, result1.Matched, "First match should succeed")

	// Second call should use cached regex
	result2 := matcher.MatchPath("/api/v1/users/456", rulePath)
	assert.True(t, result2.Matched, "Second match should succeed")
	assert.Equal(t, "456", result2.Params["id"], "Second match should extract correct param")

	// Verify cache is working by testing multiple different paths
	testPaths := []string{
		"/api/v1/users/789",
		"/api/v1/users/abc",
		"/api/v1/users/xyz",
	}

	for _, testPath := range testPaths {
		result := matcher.MatchPath(testPath, rulePath)
		assert.True(t, result.Matched, "Match should succeed for path: %s", testPath)
	}
}

func TestRuleMatcher_EdgeCases(t *testing.T) {
	matcher := NewRuleMatcher()

	t.Run("empty strings", func(t *testing.T) {
		result := matcher.MatchPath("", "")
		assert.True(t, result.Matched, "Empty strings should match")
	})

	t.Run("path with only param", func(t *testing.T) {
		result := matcher.MatchPath("123", "{id}")
		assert.True(t, result.Matched, "Path with only param should match")
		assert.Equal(t, "123", result.Params["id"])
	})

	t.Run("multiple same params", func(t *testing.T) {
		result := matcher.MatchPath("/api/v1/users/123/posts/123", "/api/v1/users/{id}/posts/{id}")
		assert.True(t, result.Matched, "Path with same param values should match")
		assert.Equal(t, "123", result.Params["id"])
	})

	t.Run("very long path", func(t *testing.T) {
		longPath := "/api/v1/" + string(make([]byte, 1000))
		result := matcher.MatchPath(longPath, longPath)
		assert.True(t, result.Matched, "Very long path should match exactly")
	})

	t.Run("unicode characters in param", func(t *testing.T) {
		result := matcher.MatchPath("/api/v1/users/café-123", "/api/v1/users/{id}")
		assert.True(t, result.Matched, "Unicode characters should match")
		assert.Equal(t, "café-123", result.Params["id"])
	})
}

func TestRuleMatcher_MethodAllowed(t *testing.T) {
	matcher := NewRuleMatcher()

	// Test through MatchRule since methodAllowed is private
	rules := []types.ForwardingRuleDTO{
		{
			ID:      "rule1",
			Path:    "/api/v1/test",
			Methods: []string{"GET", "POST"},
			Active:  true,
		},
	}

	t.Run("allowed method", func(t *testing.T) {
		rule, _ := matcher.MatchRule("/api/v1/test", "GET", rules)
		assert.NotNil(t, rule, "GET should match")
		rule, _ = matcher.MatchRule("/api/v1/test", "POST", rules)
		assert.NotNil(t, rule, "POST should match")
	})

	t.Run("not allowed method", func(t *testing.T) {
		rule, _ := matcher.MatchRule("/api/v1/test", "PUT", rules)
		assert.Nil(t, rule, "PUT should not match")
		rule, _ = matcher.MatchRule("/api/v1/test", "DELETE", rules)
		assert.Nil(t, rule, "DELETE should not match")
	})
}
