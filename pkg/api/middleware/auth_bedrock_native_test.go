// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package middleware_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	nativePath = "/cons1234/model/amazon.nova-lite-v1%3A0/converse"
	// An AWS SDK signs every call, so this is what boto3 sends to the gateway.
	sigV4Authorization = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260101/us-east-1/bedrock/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc"
)

type awsError struct {
	Type    string `json:"__type"`
	Message string `json:"message"`
	Error   string `json:"error"`
}

func nativeRequest(path string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(fiber.MethodPost, path, nil)
	req.Host = "acme.gw.neuraltrust.ai"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func readAWSError(t *testing.T, resp *http.Response) awsError {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var out awsError
	require.NoError(t, json.Unmarshal(raw, &out), string(raw))
	return out
}

func TestAuthMiddleware_NativeBedrock_APIKeyBesideSigV4Authenticates(t *testing.T) {
	t.Parallel()
	gw, rc, rawKey := inlineConsumerWithAPIKey(t)
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeOIDCVerifier{})

	// boto3 sends the gateway key in a header of its own and signs as usual.
	resp, err := app.Test(nativeRequest(nativePath, map[string]string{
		resolver.HeaderAPIKey:     rawKey,
		fiber.HeaderAuthorization: sigV4Authorization,
	}))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

func TestAuthMiddleware_NativeBedrock_BearerAPIKeyAuthenticates(t *testing.T) {
	t.Parallel()
	gw, rc, rawKey := inlineConsumerWithAPIKey(t)
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeOIDCVerifier{})

	// AWS_BEARER_TOKEN_BEDROCK makes the SDK send a plain bearer instead.
	resp, err := app.Test(nativeRequest(nativePath, map[string]string{
		fiber.HeaderAuthorization: "Bearer " + rawKey,
	}))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)
}

// Without the guard a SigV4 Authorization went to the bearer parser and came
// back as a 400 "malformed bearer", which hid that the key was simply missing.
func TestAuthMiddleware_NativeBedrock_SigV4AloneIsUnauthenticatedNotMalformed(t *testing.T) {
	t.Parallel()
	gw, rc, _ := inlineConsumerWithAPIKey(t)
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeOIDCVerifier{})

	resp, err := app.Test(nativeRequest(nativePath, map[string]string{
		fiber.HeaderAuthorization: sigV4Authorization,
	}))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, "UnrecognizedClientException", resp.Header.Get("X-Amzn-Errortype"))
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
	body := readAWSError(t, resp)
	assert.Equal(t, "UnrecognizedClientException", body.Type)
	assert.Equal(t, "unauthenticated", body.Error, "the gateway's own code stays in the body")
	assert.NotEmpty(t, body.Message)
}

func TestAuthMiddleware_NativeBedrock_SigV4OnAnotherRouteKeepsItsBehaviour(t *testing.T) {
	t.Parallel()
	gw, rc, _ := inlineConsumerWithAPIKey(t)
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeOIDCVerifier{})

	resp, err := app.Test(nativeRequest("/cons1234/v1/chat/completions", map[string]string{
		fiber.HeaderAuthorization: sigV4Authorization,
	}))
	require.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, resp.StatusCode, "the guard is for native Bedrock routes only")
	assert.Empty(t, resp.Header.Get("X-Amzn-Errortype"))
	assert.Equal(t, "invalid_auth_request", decodeAuthErrorBody(t, resp).Error)
}

func TestAuthMiddleware_NativeBedrock_ErrorsUseTheAWSEnvelope(t *testing.T) {
	t.Parallel()
	gw, rc, rawKey := inlineConsumerWithAPIKey(t)
	data := appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc})
	tests := []struct {
		name       string
		path       string
		headers    map[string]string
		data       *appconsumer.Data
		wantStatus int
		wantType   string
		wantCode   string
	}{
		{
			name:       "unknown consumer",
			path:       nativePath,
			headers:    map[string]string{resolver.HeaderAPIKey: rawKey},
			data:       appconsumer.NewData(gw.ID, nil),
			wantStatus: fiber.StatusNotFound,
			wantType:   "ResourceNotFoundException",
			wantCode:   "not_found",
		},
		{
			name:       "wrong key",
			path:       nativePath,
			headers:    map[string]string{resolver.HeaderAPIKey: "ag_wrong"},
			data:       data,
			wantStatus: fiber.StatusUnauthorized,
			wantType:   "UnrecognizedClientException",
			wantCode:   "unauthenticated",
		},
		{
			name:       "refused model identifier",
			path:       "/cons1234/model/%2e%2e/converse",
			headers:    map[string]string{resolver.HeaderAPIKey: rawKey},
			data:       data,
			wantStatus: fiber.StatusBadRequest,
			wantType:   "ValidationException",
			wantCode:   "invalid_model",
		},
		{
			name:       "slash outside an ARN",
			path:       "/cons1234/model/anthropic%2Fclaude/invoke",
			headers:    map[string]string{resolver.HeaderAPIKey: rawKey},
			data:       data,
			wantStatus: fiber.StatusBadRequest,
			wantType:   "ValidationException",
			wantCode:   "invalid_model",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			app := newAuthTestApp(t, gw, tt.data, fakeOAuth2Verifier{}, fakeOIDCVerifier{})
			resp, err := app.Test(nativeRequest(tt.path, tt.headers))
			require.NoError(t, err)
			require.Equal(t, tt.wantStatus, resp.StatusCode)
			assert.Equal(t, tt.wantType, resp.Header.Get("X-Amzn-Errortype"))
			body := readAWSError(t, resp)
			assert.Equal(t, tt.wantType, body.Type)
			assert.Equal(t, tt.wantCode, body.Error)
		})
	}
}

func TestAuthMiddleware_NativeBedrock_GatewayFailuresUseTheAWSEnvelope(t *testing.T) {
	t.Parallel()
	gw, rc, rawKey := inlineConsumerWithAPIKey(t)
	data := appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc})
	app := newAuthTestAppWithResolver(t,
		fakeGatewayResolver{gateway: gw, err: assert.AnError}, data, fakeOAuth2Verifier{}, fakeOIDCVerifier{})

	resp, err := app.Test(nativeRequest(nativePath, map[string]string{resolver.HeaderAPIKey: rawKey}))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)
	assert.Equal(t, "InternalServerException", resp.Header.Get("X-Amzn-Errortype"))
}

func TestAuthMiddleware_NonNativeErrorsAreUnchanged(t *testing.T) {
	t.Parallel()
	gw, rc, _ := inlineConsumerWithAPIKey(t)
	app := newAuthTestApp(t, gw, appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc}), fakeOAuth2Verifier{}, fakeOIDCVerifier{})

	resp, err := app.Test(nativeRequest("/cons1234/v1/chat/completions", nil))
	require.NoError(t, err)
	require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("X-Amzn-Errortype"))
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.JSONEq(t, `{"error":"unauthenticated","message":"unauthenticated"}`, string(raw))
}

// A native Bedrock path is never a store path: the store slug addresses the LLM
// store of personal keys, which serves the OpenAI-shaped routes only. Under it a
// native path is an unknown route, answered before any key is looked at, and its
// refused model identifier is not a 400 either.
func TestAuthMiddleware_NativeBedrockPathsAreNotStorePaths(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/store/model/amazon.nova-lite-v1%3A0/converse",
		"/store/model/amazon.nova-lite-v1%3A0/invoke-with-response-stream",
		"/store/model/%2e%2e/converse",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			f := newStoreFixture(t)
			app := f.app(nil)
			for _, key := range []string{"", f.appKey, "ag_alice"} {
				req := nativeRequest(path, map[string]string{resolver.HeaderAPIKey: key})
				resp, err := app.Test(req)
				require.NoError(t, err)
				require.Equal(t, fiber.StatusNotFound, resp.StatusCode, key)
				assert.Empty(t, resp.Header.Get("X-Amzn-Errortype"), "not an AWS route, so not an AWS envelope")
				assert.Equal(t, "not_found", decodeAuthErrorBody(t, resp).Error)
			}
			assert.Zero(t, f.finder.calls.Load(), "no key was looked up")
		})
	}
}

// What the store accepts is untouched by the native route: personal keys stay
// off application routes native ones included, an expired key is refused there,
// and a SigV4 Authorization is no credential on the store.
func TestAuthMiddleware_NativeBedrockLeavesPersonalAndExpiredKeyRulesAlone(t *testing.T) {
	t.Parallel()
	t.Run("a personal key is not accepted on a native application route", func(t *testing.T) {
		t.Parallel()
		f := newStoreFixture(t)
		resp, err := f.app(nil).Test(nativeRequest(nativePath, map[string]string{resolver.HeaderAPIKey: "ag_alice"}))
		require.NoError(t, err)
		require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, "UnrecognizedClientException", resp.Header.Get("X-Amzn-Errortype"))
	})
	t.Run("an expired application key is refused on a native route", func(t *testing.T) {
		t.Parallel()
		f := newStoreFixture(t)
		past := authTestNow.Add(-time.Hour)
		f.consumers[0].Auths[0].ExpiresAt = &past
		resp, err := f.app(nil).Test(nativeRequest(nativePath, map[string]string{
			resolver.HeaderAPIKey:     f.appKey,
			fiber.HeaderAuthorization: sigV4Authorization,
		}))
		require.NoError(t, err)
		require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, "UnrecognizedClientException", resp.Header.Get("X-Amzn-Errortype"))
	})
	t.Run("a valid application key with SigV4 still gets through", func(t *testing.T) {
		t.Parallel()
		f := newStoreFixture(t)
		resp, err := f.app(nil).Test(nativeRequest(nativePath, map[string]string{
			resolver.HeaderAPIKey:     f.appKey,
			fiber.HeaderAuthorization: sigV4Authorization,
		}))
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
	})
	t.Run("a SigV4 Authorization is no credential on the store", func(t *testing.T) {
		t.Parallel()
		f := newStoreFixture(t)
		status, _ := callStore(t, f.app(nil), storeChatPath, fiber.HeaderAuthorization, sigV4Authorization)
		assert.Equal(t, fiber.StatusUnauthorized, status)
	})
	t.Run("an expired personal key is refused on the store", func(t *testing.T) {
		t.Parallel()
		f := newStoreFixture(t)
		f.finder.keys["ag_expired"] = &authdomain.Auth{ID: ids.New[ids.AuthKind](), GatewayID: f.gw.ID, Type: authdomain.TypeAPIKey,
			Enabled: true, KeyHash: authdomain.HashAPIKey("ag_expired"), OwnerID: "alice", ExpiresAt: &authTestNow}
		status, _ := callStore(t, f.app(nil), storeChatPath, resolver.HeaderAPIKey, "ag_expired")
		assert.Equal(t, fiber.StatusUnauthorized, status)
	})
}
