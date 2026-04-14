package http

import (
	"context"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/rule"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	domainUpstream "github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/handlers/http/helpers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

func TestRewriteTargetURL_VertexPassthrough(t *testing.T) {
	h := &forwardedHandler{
		ruleMatcher: rule.NewRuleMatcher(),
	}

	vertexPathPattern := "/{version}/projects/{project}/locations/{location}/publishers/{publisher}/models/{model_action}"

	tests := []struct {
		name       string
		pathParams map[string]string
		targetPath string
		stripPath  bool
		wantURL    string
	}{
		{
			name: "v1 generateContent passthrough reconstructs original path",
			pathParams: map[string]string{
				"version":      "v1",
				"project":      "my-proj",
				"location":     "us-central1",
				"publisher":    "google",
				"model_action": "gemini-2.5-flash:generateContent",
			},
			targetPath: vertexPathPattern,
			stripPath:  false,
			wantURL:    "https://us-central1-aiplatform.googleapis.com/v1/projects/my-proj/locations/us-central1/publishers/google/models/gemini-2.5-flash:generateContent",
		},
		{
			name: "v1beta1 streamGenerateContent passthrough",
			pathParams: map[string]string{
				"version":      "v1beta1",
				"project":      "prod-project",
				"location":     "europe-west4",
				"publisher":    "google",
				"model_action": "gemini-2.5-pro:streamGenerateContent",
			},
			targetPath: vertexPathPattern,
			stripPath:  false,
			wantURL:    "https://us-central1-aiplatform.googleapis.com/v1beta1/projects/prod-project/locations/europe-west4/publishers/google/models/gemini-2.5-pro:streamGenerateContent",
		},
		{
			name: "embedContent passthrough",
			pathParams: map[string]string{
				"version":      "v1",
				"project":      "my-proj",
				"location":     "us-central1",
				"publisher":    "google",
				"model_action": "gemini-embedding-001:embedContent",
			},
			targetPath: vertexPathPattern,
			stripPath:  false,
			wantURL:    "https://us-central1-aiplatform.googleapis.com/v1/projects/my-proj/locations/us-central1/publishers/google/models/gemini-embedding-001:embedContent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), common.PathParamsKey, tt.pathParams)

			dto := &forwardedRequestDTO{
				req: &types.RequestContext{
					Context: ctx,
					Path:    "/" + tt.pathParams["version"] + "/projects/" + tt.pathParams["project"] + "/locations/" + tt.pathParams["location"] + "/publishers/" + tt.pathParams["publisher"] + "/models/" + tt.pathParams["model_action"],
				},
				rule: &types.ForwardingRuleDTO{
					Path:      vertexPathPattern,
					StripPath: tt.stripPath,
				},
				target: &types.UpstreamTargetDTO{
					Host:     "us-central1-aiplatform.googleapis.com",
					Port:     443,
					Protocol: "https",
					Path:     tt.targetPath,
				},
			}

			got := h.rewriteTargetURL(dto)
			assert.Equal(t, tt.wantURL, got)
		})
	}
}

func TestRewriteTargetURL_WildcardStripPath(t *testing.T) {
	h := &forwardedHandler{
		ruleMatcher: rule.NewRuleMatcher(),
	}

	tests := []struct {
		name        string
		rulePath    string
		requestPath string
		pathParams  map[string]string
		stripPath   bool
		targetPath  string
		wantURL     string
	}{
		{
			name:        "wildcard strip single segment",
			rulePath:    "/v1/*",
			requestPath: "/v1/users/123",
			pathParams:  map[string]string{"*": "users/123"},
			stripPath:   true,
			targetPath:  "/api",
			wantURL:     "https://backend:8080/api/users/123",
		},
		{
			name:        "wildcard no strip keeps base URL",
			rulePath:    "/v1/*",
			requestPath: "/v1/users/123",
			pathParams:  map[string]string{"*": "users/123"},
			stripPath:   false,
			targetPath:  "/api",
			wantURL:     "https://backend:8080/api",
		},
		{
			name:        "deeper wildcard prefix strips correctly",
			rulePath:    "/v1/api/*",
			requestPath: "/v1/api/users",
			pathParams:  map[string]string{"*": "users"},
			stripPath:   true,
			targetPath:  "/backend",
			wantURL:     "https://backend:8080/backend/users",
		},
		{
			name:        "wildcard with param before it",
			rulePath:    "/v1/{id}/*",
			requestPath: "/v1/123/posts/456",
			pathParams:  map[string]string{"id": "123", "*": "posts/456"},
			stripPath:   true,
			targetPath:  "/api",
			wantURL:     "https://backend:8080/api/posts/456",
		},
		{
			name:        "wildcard deep multi-segment path",
			rulePath:    "/v1/*",
			requestPath: "/v1/a/b/c/d",
			pathParams:  map[string]string{"*": "a/b/c/d"},
			stripPath:   true,
			targetPath:  "",
			wantURL:     "https://backend:8080/a/b/c/d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), common.PathParamsKey, tt.pathParams)

			dto := &forwardedRequestDTO{
				req: &types.RequestContext{
					Context: ctx,
					Path:    tt.requestPath,
				},
				rule: &types.ForwardingRuleDTO{
					Path:        tt.rulePath,
					MatchedPath: tt.rulePath,
					StripPath:   tt.stripPath,
				},
				target: &types.UpstreamTargetDTO{
					Host:     "backend",
					Port:     8080,
					Protocol: "https",
					Path:     tt.targetPath,
				},
			}

			got := h.rewriteTargetURL(dto)
			assert.Equal(t, tt.wantURL, got)
		})
	}
}

func TestBuildFastHTTPRequest_OAuthHeaderInjection(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	h := &forwardedHandler{logger: logger}

	oauthToken := "test-oauth-token" // #nosec G101 -- test stub, not a real credential

	dto := &forwardedRequestDTO{
		req: &types.RequestContext{
			Method: "POST",
			Body:   []byte(`{"contents":[{"parts":[{"text":"hello"}]}]}`),
			Headers: map[string][]string{
				"Content-Type":  {"application/json"},
				"Authorization": {"Bearer " + oauthToken},
			},
		},
		target: &types.UpstreamTargetDTO{
			Headers: map[string]string{
				"Authorization": "Bearer " + oauthToken,
			},
		},
	}

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	h.buildFastHTTPRequest(req, dto, "https://us-central1-aiplatform.googleapis.com/v1/projects/p/locations/l/publishers/google/models/m:generateContent")

	assert.Equal(t, "Bearer "+oauthToken, string(req.Header.Peek("Authorization")))
	assert.Equal(t, "application/json", string(req.Header.Peek("Content-Type")))
	assert.Equal(t, "POST", string(req.Header.Method()))
}

type stubTokenClient struct {
	token     string
	expiresAt time.Time
	err       error
}

func (s *stubTokenClient) GetToken(_ context.Context, _ oauth.TokenRequestDTO) (string, time.Time, error) {
	return s.token, s.expiresAt, s.err
}

func TestApplyTargetAuth_InjectsBearer(t *testing.T) {
	fakeToken := "test-oauth-token" // #nosec G101 -- test stub, not a real credential

	deps := helpers.AuthDeps{
		TokenClient: &stubTokenClient{
			token:     fakeToken,
			expiresAt: time.Now().Add(time.Hour),
		},
	}

	targetID := "target-1"

	req := &types.RequestContext{
		Context: context.Background(),
	}

	target := &types.UpstreamTargetDTO{
		ID: targetID,
	}

	upstreamModel := &domainUpstream.Upstream{
		Targets: []domainUpstream.Target{
			{
				ID: targetID,
				Auth: &domainUpstream.TargetAuth{
					Type: domainUpstream.AuthTypeOAuth2,
					OAuth: &domainUpstream.TargetOAuthConfig{
						TokenURL:     "https://oauth2.googleapis.com/token",
						GrantType:    "client_credentials",
						ClientID:     "test-client-id",
						ClientSecret: "test-client-secret",
						Scopes:       []string{"https://www.googleapis.com/auth/cloud-platform"},
					},
				},
			},
		},
	}

	err := helpers.ApplyTargetAuth(deps, req, target, upstreamModel)
	require.NoError(t, err)

	assert.Equal(t, []string{"Bearer " + fakeToken}, req.Headers["Authorization"])
	assert.Equal(t, "Bearer "+fakeToken, target.Headers["Authorization"])
}

func TestApplyTargetAuth_NoAuth_NoHeaders(t *testing.T) {
	deps := helpers.AuthDeps{
		TokenClient: &stubTokenClient{},
	}

	req := &types.RequestContext{Context: context.Background()}
	target := &types.UpstreamTargetDTO{ID: "t1"}

	upstreamModel := &domainUpstream.Upstream{
		Targets: []domainUpstream.Target{
			{ID: "t1"},
		},
	}

	err := helpers.ApplyTargetAuth(deps, req, target, upstreamModel)
	require.NoError(t, err)
	assert.Nil(t, req.Headers)
	assert.Nil(t, target.Headers)
}
