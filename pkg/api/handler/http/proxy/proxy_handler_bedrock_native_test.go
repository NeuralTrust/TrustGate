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

package proxy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	proxyhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/proxy"
	apiresolver "github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/TrustGate/pkg/app/proxy/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const nativeEncodedARN = "arn%3Aaws%3Abedrock%3Aus-east-1%3A123456789012%3Ainference-profile%2Fus.anthropic.claude-3-5-sonnet-20241022-v2%3A0"

func nativeHTTPRequest(path, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func newNativeApp(t *testing.T) (*fiber.App, *proxymocks.Forwarder) {
	t.Helper()
	fwd := proxymocks.NewForwarder(t)
	app := fiber.New()
	app.Use(authStub(ids.New[ids.GatewayKind](), consumerSlug))
	app.All("/*", proxyhttp.NewForwardedHandler(fwd).WithLogger(slog.New(slog.DiscardHandler)).Handle)
	return app, fwd
}

func nativeFrame(t *testing.T, eventType, payload string) []byte {
	t.Helper()
	var headers eventstream.Headers
	headers.Set(":message-type", eventstream.StringValue("event"))
	headers.Set(":event-type", eventstream.StringValue(eventType))
	headers.Set(":content-type", eventstream.StringValue("application/json"))
	var buf bytes.Buffer
	require.NoError(t, eventstream.NewEncoder().Encode(&buf, eventstream.Message{Headers: headers, Payload: []byte(payload)}))
	return buf.Bytes()
}

func TestHandle_NativeBedrock_BuildsTheRequestContextFromTheRawPath(t *testing.T) {
	cases := []struct {
		name       string
		path       string
		wantOp     string
		wantRaw    string
		wantModel  string
		wantStream bool
	}{
		{"encoded ARN stays encoded in the raw id", "/" + consumerSlug + "/model/" + nativeEncodedARN + "/converse",
			"converse", nativeEncodedARN, "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-3-5-sonnet-20241022-v2:0", false},
		{"plain id with an encoded colon", "/" + consumerSlug + "/model/amazon.nova-lite-v1%3A0/converse-stream",
			"converse-stream", "amazon.nova-lite-v1%3A0", "amazon.nova-lite-v1:0", true},
		{"invoke", "/" + consumerSlug + "/model/amazon.titan-text-express-v1/invoke",
			"invoke", "amazon.titan-text-express-v1", "amazon.titan-text-express-v1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, fwd := newNativeApp(t)
			var got *infracontext.RequestContext
			fwd.EXPECT().
				Forward(mock.Anything, mock.Anything).
				Run(func(_ context.Context, in appproxy.ForwardInput) { got = in.Request }).
				Return(&appproxy.ForwardResult{StatusCode: 200, Body: []byte(`{}`), Upstream: true}, nil).
				Once()

			resp, err := app.Test(nativeHTTPRequest(tc.path, `{"messages":[]}`))
			require.NoError(t, err)
			require.Equal(t, 200, resp.StatusCode)
			require.NotNil(t, got)
			require.NotNil(t, got.BedrockNative)
			assert.Equal(t, tc.wantOp, string(got.BedrockNative.Op))
			assert.Equal(t, tc.wantRaw, got.BedrockNative.RawModelID)
			assert.Equal(t, tc.wantModel, got.BedrockNative.ModelID)
			assert.Equal(t, got.BedrockNative.IsStream(), tc.wantStream)
			assert.Equal(t, "bedrock_native", got.SourceFormat)
			assert.Equal(t, "bedrock_native", got.ProxyCapability)
			assert.Equal(t, `{"messages":[]}`, string(got.Body))
		})
	}
}

func TestHandle_NativeBedrock_OnlyPOSTIsAllowed(t *testing.T) {
	app, _ := newNativeApp(t)
	req := httptest.NewRequest(http.MethodGet, "/"+consumerSlug+"/model/amazon.nova-lite-v1:0/converse", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
	assert.Equal(t, "POST", resp.Header.Get("Allow"))
	assert.Equal(t, "ValidationException", resp.Header.Get("X-Amzn-Errortype"))
}

func TestHandle_NativeBedrock_UpstreamAnswersAreRelayedAsAWSSentThem(t *testing.T) {
	const awsBody = `{"message":"The provided model identifier is invalid."}`
	app, fwd := newNativeApp(t)
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(&appproxy.ForwardResult{
			StatusCode: http.StatusBadRequest,
			Headers: map[string][]string{
				"Content-Type":     {"application/json"},
				"X-Amzn-Errortype": {"ValidationException:http://internal.amazon.com/coral/com.amazon.bedrock/"},
				"X-Amzn-Requestid": {"aws-request-id"},
			},
			Body:     []byte(awsBody),
			Upstream: true,
		}, nil).
		Once()

	resp, err := app.Test(nativeHTTPRequest("/"+consumerSlug+"/model/m/converse", `{}`))
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "ValidationException:http://internal.amazon.com/coral/com.amazon.bedrock/", resp.Header.Get("X-Amzn-Errortype"),
		"AWS's own error type, suffix included, must not be rewritten")
	assert.Equal(t, "aws-request-id", resp.Header.Get("X-Amzn-Requestid"))
	raw, _ := io.ReadAll(resp.Body)
	assert.Equal(t, awsBody, string(raw), "an AWS error body is relayed byte for byte")
}

func TestHandle_NativeBedrock_GatewayErrorsGetTheAWSEnvelope(t *testing.T) {
	cases := []struct {
		name     string
		result   *appproxy.ForwardResult
		err      error
		status   int
		wantType string
		wantCode string
	}{
		{
			name: "plugin block",
			result: &appproxy.ForwardResult{
				StatusCode: 403,
				Headers:    map[string][]string{"Content-Type": {"application/json"}},
				Body:       []byte(`{"error":"plugin_rejected","message":"blocked by policy","type":"guardrail_blocked"}`),
			},
			status: 403, wantType: "AccessDeniedException", wantCode: "plugin_rejected",
		},
		{
			name:     "rate limit",
			result:   &appproxy.ForwardResult{StatusCode: 429, Body: []byte(`{"error":"rate_limited"}`)},
			status:   429,
			wantType: "ThrottlingException",
			wantCode: "rate_limited",
		},
		{
			name:     "forwarder error: no backend",
			err:      appproxy.ErrNoBackendAvailable,
			status:   503,
			wantType: "ServiceUnavailableException",
			wantCode: "no_backend_available",
		},
		{
			name:     "forwarder error: ambiguous body",
			err:      appproxy.ErrAmbiguousRequestBody,
			status:   400,
			wantType: "ValidationException",
			wantCode: "invalid_request_body",
		},
		{
			name:     "forwarder error: model not allowed",
			err:      appproxy.ErrModelNotAllowed,
			status:   403,
			wantType: "AccessDeniedException",
			wantCode: "model_not_allowed",
		},
		{
			name:     "forwarder error: plugin error",
			err:      &appplugins.PluginError{StatusCode: 403, Message: "nope"},
			status:   403,
			wantType: "AccessDeniedException",
			wantCode: "plugin_rejected",
		},
		{
			name:     "forwarder error: anything else",
			err:      errors.New("boom"),
			status:   502,
			wantType: "InternalServerException",
			wantCode: "backend_error",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, fwd := newNativeApp(t)
			fwd.EXPECT().Forward(mock.Anything, mock.Anything).Return(tc.result, tc.err).Once()

			resp, err := app.Test(nativeHTTPRequest("/"+consumerSlug+"/model/m/converse", `{}`))
			require.NoError(t, err)
			require.Equal(t, tc.status, resp.StatusCode)
			assert.Equal(t, tc.wantType, resp.Header.Get("X-Amzn-Errortype"))
			assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
			var body map[string]any
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
			assert.Equal(t, tc.wantType, body["__type"])
			assert.Equal(t, tc.wantCode, body["error"], "the gateway's own code stays in the body")
			assert.NotEmpty(t, body["message"])
		})
	}
}

func TestHandle_NativeBedrock_PluginBlockKeepsItsPolicyFields(t *testing.T) {
	app, fwd := newNativeApp(t)
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(&appproxy.ForwardResult{
			StatusCode: 403,
			Body:       []byte(`{"error":{"type":"guardrail_blocked","message":"Request blocked by guardrail.","policy":"topic_policy","name":"DangerousTopics"}}`),
		}, nil).
		Once()

	resp, err := app.Test(nativeHTTPRequest("/"+consumerSlug+"/model/m/converse", `{}`))
	require.NoError(t, err)
	raw, _ := io.ReadAll(resp.Body)
	assert.JSONEq(t, `{
		"__type":"AccessDeniedException",
		"message":"Request blocked by guardrail.",
		"error":{"type":"guardrail_blocked","message":"Request blocked by guardrail.","policy":"topic_policy","name":"DangerousTopics"}
	}`, string(raw))
}

func TestHandle_NonNativeErrorsAreNotEnveloped(t *testing.T) {
	app, fwd := newTestApp(t)
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(&appproxy.ForwardResult{StatusCode: 403, Body: []byte(`{"error":"plugin_rejected"}`)}, nil).
		Once()

	resp, err := app.Test(newProxyRequest())
	require.NoError(t, err)
	assert.Empty(t, resp.Header.Get("X-Amzn-Errortype"))
	raw, _ := io.ReadAll(resp.Body)
	assert.JSONEq(t, `{"error":"plugin_rejected"}`, string(raw))
}

func TestHandle_NativeBedrock_StreamsRawFramesWithNoSeparator(t *testing.T) {
	frames := [][]byte{
		nativeFrame(t, "contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":"Hello"}}`),
		nativeFrame(t, "messageStop", `{"stopReason":"end_turn"}`),
	}
	stream := func(yield func([]byte, error) bool) {
		for _, f := range frames {
			if !yield(f, nil) {
				return
			}
		}
	}
	fwd := proxymocks.NewForwarder(t)
	fwd.EXPECT().
		Forward(mock.Anything, mock.Anything).
		Return(&appproxy.ForwardResult{
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"application/vnd.amazon.eventstream"}, "X-Amzn-Requestid": {"r-1"}},
			Stream:     stream,
			Upstream:   true,
			RawFrames:  true,
			StreamView: adapter.BedrockFrameView,
		}, nil).
		Once()

	var (
		mu     sync.Mutex
		output []byte
	)
	app := fiber.New()
	app.Use(authStub(ids.New[ids.GatewayKind](), consumerSlug))
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(infracontext.StreamMetricsFinalizerKey, infracontext.StreamMetricsFinalizer(
			func(_ *infracontext.RequestContext, out []byte, _ int, _ map[string][]string) {
				mu.Lock()
				defer mu.Unlock()
				output = out
			}))
		return c.Next()
	})
	app.All("/*", proxyhttp.NewForwardedHandler(fwd).Handle)

	resp, err := app.Test(nativeHTTPRequest("/"+consumerSlug+"/model/m/converse-stream", `{"messages":[]}`))
	require.NoError(t, err)
	require.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "application/vnd.amazon.eventstream", resp.Header.Get("Content-Type"))
	assert.Equal(t, "r-1", resp.Header.Get("X-Amzn-Requestid"))
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, bytes.Join(frames, nil), body, "frames must reach the client byte for byte, with no newline between them")

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t,
		"data: {\"contentBlockDelta\":{\"contentBlockIndex\":0,\"delta\":{\"text\":\"Hello\"}}}\n"+
			"data: {\"messageStop\":{\"stopReason\":\"end_turn\"}}\n",
		string(output), "metrics capture the decoded view, not the binary frames")
}

func TestHandle_NativeBedrock_MidStreamFailureEndsWithAnExceptionFrame(t *testing.T) {
	first := nativeFrame(t, "messageStart", `{"role":"assistant"}`)
	tests := map[string]func(yield func([]byte, error) bool){
		"upstream error": func(yield func([]byte, error) bool) {
			if yield(first, nil) {
				yield(nil, errors.New("connection reset"))
			}
		},
		"panic": func(yield func([]byte, error) bool) {
			if yield(first, nil) {
				panic("reader exploded")
			}
		},
	}
	for name, stream := range tests {
		t.Run(name, func(t *testing.T) {
			fwd := proxymocks.NewForwarder(t)
			fwd.EXPECT().
				Forward(mock.Anything, mock.Anything).
				Return(&appproxy.ForwardResult{StatusCode: 200, Stream: stream, Upstream: true, RawFrames: true}, nil).
				Once()
			app := fiber.New()
			app.Use(authStub(ids.New[ids.GatewayKind](), consumerSlug))
			app.All("/*", proxyhttp.NewForwardedHandler(fwd).WithLogger(slog.New(slog.DiscardHandler)).Handle)

			resp, err := app.Test(nativeHTTPRequest("/"+consumerSlug+"/model/m/converse-stream", `{}`))
			require.NoError(t, err)
			body, _ := io.ReadAll(resp.Body)
			require.True(t, bytes.HasPrefix(body, first), "the frame sent before the failure is kept")

			rest := body[len(first):]
			msg, err := eventstream.NewDecoder().Decode(bytes.NewReader(rest), nil)
			require.NoError(t, err, "what follows must be a decodable eventstream frame, not an SSE event")
			assert.Equal(t, "exception", msg.Headers.Get(":message-type").String())
			assert.Equal(t, "internalServerException", msg.Headers.Get(":exception-type").String())
			assert.NotContains(t, string(body), "data:")
		})
	}
}

// Only a native route answers in the AWS envelope: the route says so, not the
// format it was tagged with.
func TestHandle_AWSEnvelopeFollowsTheNativeRouteNotTheFormat(t *testing.T) {
	fwd := proxymocks.NewForwarder(t)
	fwd.EXPECT().Forward(mock.Anything, mock.Anything).Return(nil, errors.New("boom")).Once()
	app := fiber.New()
	app.Use(authStub(ids.New[ids.GatewayKind](), consumerSlug))
	app.Use(func(c *fiber.Ctx) error {
		c.Locals(apiresolver.ProxyRouteLocalsKey, apiresolver.ProxyRoute{
			ConsumerSlug: consumerSlug, SourceFormat: adapter.FormatBedrock, Capability: apiresolver.CapabilityChat, Rest: "/v1/chat/completions",
		})
		return c.Next()
	})
	app.All("/*", proxyhttp.NewForwardedHandler(fwd).WithLogger(slog.New(slog.DiscardHandler)).Handle)

	resp, err := app.Test(nativeHTTPRequest("/"+consumerSlug+"/v1/chat/completions", `{}`))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, resp.StatusCode, 500)
	assert.Empty(t, resp.Header.Get("X-Amzn-Errortype"), "a route that is not native keeps its own error shape")
}
