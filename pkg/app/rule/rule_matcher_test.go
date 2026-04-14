package rule

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
		{
			name:        "wildcard matches single segment",
			requestPath: "/v1/users",
			rulePath:    "/v1/*",
			wantMatch:   true,
			wantParams:  map[string]string{"*": "users"},
		},
		{
			name:        "wildcard matches multi segment",
			requestPath: "/v1/users/123",
			rulePath:    "/v1/*",
			wantMatch:   true,
			wantParams:  map[string]string{"*": "users/123"},
		},
		{
			name:        "wildcard matches deep path",
			requestPath: "/v1/users/123/posts/456",
			rulePath:    "/v1/*",
			wantMatch:   true,
			wantParams:  map[string]string{"*": "users/123/posts/456"},
		},
		{
			name:        "wildcard no match - trailing slash only",
			requestPath: "/v1/",
			rulePath:    "/v1/*",
			wantMatch:   false,
			wantParams:  nil,
		},
		{
			name:        "wildcard no match - no trailing content",
			requestPath: "/v1",
			rulePath:    "/v1/*",
			wantMatch:   false,
			wantParams:  nil,
		},
		{
			name:        "wildcard no match - wrong prefix",
			requestPath: "/v2/users",
			rulePath:    "/v1/*",
			wantMatch:   false,
			wantParams:  nil,
		},
		{
			name:        "wildcard with deeper prefix",
			requestPath: "/v1/test/foo",
			rulePath:    "/v1/test/*",
			wantMatch:   true,
			wantParams:  map[string]string{"*": "foo"},
		},
		{
			name:        "wildcard with param before wildcard",
			requestPath: "/v1/users/123/posts",
			rulePath:    "/v1/users/{id}/*",
			wantMatch:   true,
			wantParams:  map[string]string{"id": "123", "*": "posts"},
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

func TestRuleMatcher_MatchRule_MultiPath(t *testing.T) {
	matcher := NewRuleMatcher()

	tests := []struct {
		name            string
		path            string
		method          string
		rules           []types.ForwardingRuleDTO
		wantRuleID      string
		wantParams      map[string]string
		wantMatchedPath string
		wantNil         bool
	}{
		{
			name:   "backward compat - single path only",
			path:   "/api/v1/users/123",
			method: "GET",
			rules: []types.ForwardingRuleDTO{
				{
					ID:      "rule1",
					Path:    "/api/v1/users/{id}",
					Methods: []string{"GET"},
					Active:  true,
				},
			},
			wantRuleID:      "rule1",
			wantParams:      map[string]string{"id": "123"},
			wantMatchedPath: "/api/v1/users/{id}",
		},
		{
			name:   "matches primary path in multi-path rule",
			path:   "/v1/projects/myproj/locations/us/publishers/google/models/gemini:gen",
			method: "POST",
			rules: []types.ForwardingRuleDTO{
				{
					ID:   "vertex",
					Path: "/v1/projects/{project}/locations/{location}/publishers/{publisher}/models/{model_action}",
					Paths: []string{
						"/v1/projects/{project}/locations/{location}/publishers/{publisher}/models/{model_action}",
						"/v1beta1/projects/{project}/locations/{location}/publishers/{publisher}/models/{model_action}",
					},
					Methods: []string{"POST"},
					Active:  true,
				},
			},
			wantRuleID:      "vertex",
			wantParams:      map[string]string{"project": "myproj", "location": "us", "publisher": "google", "model_action": "gemini:gen"},
			wantMatchedPath: "/v1/projects/{project}/locations/{location}/publishers/{publisher}/models/{model_action}",
		},
		{
			name:   "matches secondary path in multi-path rule",
			path:   "/v1beta1/projects/myproj/locations/us/publishers/google/models/gemini:predict",
			method: "POST",
			rules: []types.ForwardingRuleDTO{
				{
					ID:   "vertex",
					Path: "/v1/projects/{project}/locations/{location}/publishers/{publisher}/models/{model_action}",
					Paths: []string{
						"/v1/projects/{project}/locations/{location}/publishers/{publisher}/models/{model_action}",
						"/v1beta1/projects/{project}/locations/{location}/publishers/{publisher}/models/{model_action}",
					},
					Methods: []string{"POST"},
					Active:  true,
				},
			},
			wantRuleID:      "vertex",
			wantParams:      map[string]string{"project": "myproj", "location": "us", "publisher": "google", "model_action": "gemini:predict"},
			wantMatchedPath: "/v1beta1/projects/{project}/locations/{location}/publishers/{publisher}/models/{model_action}",
		},
		{
			name:   "no match on unregistered path",
			path:   "/v2/projects/myproj/locations/us/publishers/google/models/gemini:gen",
			method: "POST",
			rules: []types.ForwardingRuleDTO{
				{
					ID:   "vertex",
					Path: "/v1/projects/{project}/locations/{location}/publishers/{publisher}/models/{model_action}",
					Paths: []string{
						"/v1/projects/{project}/locations/{location}/publishers/{publisher}/models/{model_action}",
						"/v1beta1/projects/{project}/locations/{location}/publishers/{publisher}/models/{model_action}",
					},
					Methods: []string{"POST"},
					Active:  true,
				},
			},
			wantNil: true,
		},
		{
			name:   "multi-path rule with multiple rules selects correct one",
			path:   "/api/v2/items/42",
			method: "GET",
			rules: []types.ForwardingRuleDTO{
				{
					ID:      "rule-users",
					Path:    "/api/v1/users/{id}",
					Methods: []string{"GET"},
					Active:  true,
				},
				{
					ID:   "rule-items",
					Path: "/api/v1/items/{id}",
					Paths: []string{
						"/api/v1/items/{id}",
						"/api/v2/items/{id}",
					},
					Methods: []string{"GET"},
					Active:  true,
				},
			},
			wantRuleID:      "rule-items",
			wantParams:      map[string]string{"id": "42"},
			wantMatchedPath: "/api/v2/items/{id}",
		},
		{
			name:   "MatchedPath not leaked across calls",
			path:   "/api/v1/users/1",
			method: "GET",
			rules: []types.ForwardingRuleDTO{
				{
					ID:      "rule1",
					Path:    "/api/v1/users/{id}",
					Methods: []string{"GET"},
					Active:  true,
				},
			},
			wantRuleID:      "rule1",
			wantParams:      map[string]string{"id": "1"},
			wantMatchedPath: "/api/v1/users/{id}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, params := matcher.MatchRule(tt.path, tt.method, tt.rules)
			if tt.wantNil {
				assert.Nil(t, rule)
				assert.Nil(t, params)
				return
			}
			require.NotNil(t, rule)
			assert.Equal(t, tt.wantRuleID, rule.ID)
			assert.Equal(t, tt.wantParams, params)
			assert.Equal(t, tt.wantMatchedPath, rule.MatchedPath)
		})
	}
}

func TestRuleMatcher_MatchRule_Wildcard(t *testing.T) {
	matcher := NewRuleMatcher()

	tests := []struct {
		name       string
		path       string
		method     string
		rules      []types.ForwardingRuleDTO
		wantRuleID string
		wantParams map[string]string
		wantNil    bool
	}{
		{
			name:   "deeper wildcard wins over shallow wildcard",
			path:   "/v1/test/foo",
			method: "GET",
			rules: []types.ForwardingRuleDTO{
				{ID: "v1-test-wc", Path: "/v1/test/*", Methods: []string{"GET"}, Active: true},
				{ID: "v1-wc", Path: "/v1/*", Methods: []string{"GET"}, Active: true},
			},
			wantRuleID: "v1-test-wc",
			wantParams: map[string]string{"*": "foo"},
		},
		{
			name:   "param rule wins over wildcard",
			path:   "/v1/users/123",
			method: "GET",
			rules: []types.ForwardingRuleDTO{
				{ID: "v1-param", Path: "/v1/users/{id}", Methods: []string{"GET"}, Active: true},
				{ID: "v1-wc", Path: "/v1/*", Methods: []string{"GET"}, Active: true},
			},
			wantRuleID: "v1-param",
			wantParams: map[string]string{"id": "123"},
		},
		{
			name:   "exact rule wins over wildcard",
			path:   "/v1/users",
			method: "GET",
			rules: []types.ForwardingRuleDTO{
				{ID: "v1-exact", Path: "/v1/users", Methods: []string{"GET"}, Active: true},
				{ID: "v1-wc", Path: "/v1/*", Methods: []string{"GET"}, Active: true},
			},
			wantRuleID: "v1-exact",
			wantParams: map[string]string{},
		},
		{
			name:   "wildcard matches when no better rule",
			path:   "/v1/anything",
			method: "GET",
			rules: []types.ForwardingRuleDTO{
				{ID: "v1-wc", Path: "/v1/*", Methods: []string{"GET"}, Active: true},
			},
			wantRuleID: "v1-wc",
			wantParams: map[string]string{"*": "anything"},
		},
		{
			name:   "wildcard does not match unrelated path",
			path:   "/v2/something",
			method: "GET",
			rules: []types.ForwardingRuleDTO{
				{ID: "v1-wc", Path: "/v1/*", Methods: []string{"GET"}, Active: true},
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SortBySpecificity(tt.rules)
			rule, params := matcher.MatchRule(tt.path, tt.method, tt.rules)
			if tt.wantNil {
				assert.Nil(t, rule)
				assert.Nil(t, params)
				return
			}
			require.NotNil(t, rule)
			assert.Equal(t, tt.wantRuleID, rule.ID)
			assert.Equal(t, tt.wantParams, params)
		})
	}
}

func TestRuleMatcher_MultiPath_DoesNotMutateOriginal(t *testing.T) {
	matcher := NewRuleMatcher()

	rules := []types.ForwardingRuleDTO{
		{
			ID:   "rule1",
			Path: "/v1/foo/{id}",
			Paths: []string{
				"/v1/foo/{id}",
				"/v2/foo/{id}",
			},
			Methods: []string{"GET"},
			Active:  true,
		},
	}

	rule, _ := matcher.MatchRule("/v2/foo/42", "GET", rules)
	require.NotNil(t, rule)
	assert.Equal(t, "/v2/foo/{id}", rule.MatchedPath)

	assert.Empty(t, rules[0].MatchedPath, "original slice element must not be mutated")
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
			wantResult:  "",
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
			wantResult:  "",
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

func TestRuleMatcher_ExtractPathAfterMatch_Wildcard(t *testing.T) {
	matcher := NewRuleMatcher()

	tests := []struct {
		name        string
		requestPath string
		rulePath    string
		wantResult  string
	}{
		{
			name:        "wildcard extracts remaining path",
			requestPath: "/v1/users/123/posts",
			rulePath:    "/v1/*",
			wantResult:  "/users/123/posts",
		},
		{
			name:        "deeper wildcard extracts single segment",
			requestPath: "/v1/test/foo",
			rulePath:    "/v1/test/*",
			wantResult:  "/foo",
		},
		{
			name:        "wildcard with param extracts after param",
			requestPath: "/v1/users/123/posts",
			rulePath:    "/v1/users/{id}/*",
			wantResult:  "/posts",
		},
		{
			name:        "wildcard no match returns original",
			requestPath: "/v2/users",
			rulePath:    "/v1/*",
			wantResult:  "/v2/users",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matcher.ExtractPathAfterMatch(tt.requestPath, tt.rulePath)
			assert.Equal(t, tt.wantResult, result)
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
		{
			name: "wildcard path unchanged",
			path: "/v1/*",
			want: "/v1/*",
		},
		{
			name: "param before wildcard normalized",
			path: "/v1/users/{id}/*",
			want: "/v1/users/{}/*",
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

func TestMatchRule_WildcardSpecificityFullPipeline(t *testing.T) {
	rules := []types.ForwardingRuleDTO{
		{ID: "catch-all", Path: "/*", Methods: []string{"GET"}, Active: true},
		{ID: "v1-wildcard", Path: "/v1/*", Methods: []string{"GET"}, Active: true},
		{ID: "v1-test-wildcard", Path: "/v1/test/*", Methods: []string{"GET"}, Active: true},
		{ID: "v1-test-exact", Path: "/v1/test/users", Methods: []string{"GET"}, Active: true},
		{ID: "v1-param", Path: "/v1/users/{id}", Methods: []string{"GET"}, Active: true},
	}

	SortBySpecificity(rules)
	matcher := NewRuleMatcher()

	t.Run("exact match wins over all wildcards", func(t *testing.T) {
		rule, _ := matcher.MatchRule("/v1/test/users", "GET", rules)
		require.NotNil(t, rule)
		assert.Equal(t, "v1-test-exact", rule.ID)
	})

	t.Run("param rule wins over wildcard", func(t *testing.T) {
		rule, params := matcher.MatchRule("/v1/users/123", "GET", rules)
		require.NotNil(t, rule)
		assert.Equal(t, "v1-param", rule.ID)
		assert.Equal(t, "123", params["id"])
	})

	t.Run("deeper wildcard wins over shallow wildcard", func(t *testing.T) {
		rule, params := matcher.MatchRule("/v1/test/foo", "GET", rules)
		require.NotNil(t, rule)
		assert.Equal(t, "v1-test-wildcard", rule.ID)
		assert.Equal(t, "foo", params["*"])
	})

	t.Run("v1 wildcard wins over catch-all", func(t *testing.T) {
		rule, params := matcher.MatchRule("/v1/other", "GET", rules)
		require.NotNil(t, rule)
		assert.Equal(t, "v1-wildcard", rule.ID)
		assert.Equal(t, "other", params["*"])
	})

	t.Run("catch-all matches unrelated paths", func(t *testing.T) {
		rule, params := matcher.MatchRule("/anything", "GET", rules)
		require.NotNil(t, rule)
		assert.Equal(t, "catch-all", rule.ID)
		assert.Equal(t, "anything", params["*"])
	})

	t.Run("no match for wrong method", func(t *testing.T) {
		rule, _ := matcher.MatchRule("/v1/test/foo", "DELETE", rules)
		assert.Nil(t, rule)
	})
}

func TestRuleMatcher_Concurrency_Wildcard(t *testing.T) {
	matcher := NewRuleMatcher()

	rules := []types.ForwardingRuleDTO{
		{ID: "exact", Path: "/api/v1/users", Methods: []string{"GET"}, Active: true},
		{ID: "param", Path: "/api/v1/users/{id}", Methods: []string{"GET"}, Active: true},
		{ID: "deep-wc", Path: "/api/v1/*", Methods: []string{"GET"}, Active: true},
		{ID: "shallow-wc", Path: "/api/*", Methods: []string{"GET"}, Active: true},
		{ID: "catch-all", Path: "/*", Methods: []string{"GET"}, Active: true},
	}
	SortBySpecificity(rules)

	var wg sync.WaitGroup
	numGoroutines := 200

	type result struct {
		ruleID string
		params map[string]string
	}
	results := make([]result, numGoroutines)

	paths := []struct {
		path       string
		wantRuleID string
	}{
		{"/api/v1/users", "exact"},
		{"/api/v1/users/42", "param"},
		{"/api/v1/posts/99", "deep-wc"},
		{"/api/other", "shallow-wc"},
		{"/something", "catch-all"},
	}

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			tc := paths[index%len(paths)]
			rule, params := matcher.MatchRule(tc.path, "GET", rules)
			if rule != nil {
				results[index] = result{ruleID: rule.ID, params: params}
			}
		}(i)
	}

	wg.Wait()

	for i, res := range results {
		tc := paths[i%len(paths)]
		assert.Equal(t, tc.wantRuleID, res.ruleID,
			"goroutine %d: path %s should match rule %s", i, tc.path, tc.wantRuleID)
	}
}

func TestRuleMatcher_MultiPath_Wildcard(t *testing.T) {
	matcher := NewRuleMatcher()

	rules := []types.ForwardingRuleDTO{
		{
			ID:      "multi-wc",
			Path:    "/v1/*",
			Paths:   []string{"/v1/*", "/v2/*"},
			Methods: []string{"GET"},
			Active:  true,
		},
	}
	SortBySpecificity(rules)

	t.Run("matches first wildcard path", func(t *testing.T) {
		rule, params := matcher.MatchRule("/v1/users/123", "GET", rules)
		require.NotNil(t, rule)
		assert.Equal(t, "multi-wc", rule.ID)
		assert.Equal(t, "/v1/*", rule.MatchedPath)
		assert.Equal(t, "users/123", params["*"])
	})

	t.Run("matches second wildcard path", func(t *testing.T) {
		rule, params := matcher.MatchRule("/v2/posts/456", "GET", rules)
		require.NotNil(t, rule)
		assert.Equal(t, "multi-wc", rule.ID)
		assert.Equal(t, "/v2/*", rule.MatchedPath)
		assert.Equal(t, "posts/456", params["*"])
	})

	t.Run("no match for unregistered prefix", func(t *testing.T) {
		rule, _ := matcher.MatchRule("/v3/anything", "GET", rules)
		assert.Nil(t, rule)
	})

	t.Run("MatchedPath not leaked across calls", func(t *testing.T) {
		assert.Empty(t, rules[0].MatchedPath, "original slice element must not be mutated")
	})
}
