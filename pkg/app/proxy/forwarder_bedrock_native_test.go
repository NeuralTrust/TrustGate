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
	"context"
	"encoding/base64"
	"github.com/NeuralTrust/TrustGate/pkg/domain/bedrocknative"
	"net/http"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/TrustGate/pkg/app/proxy/mocks"
	domainconsumer "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	nativeConverseBody = "{ \"messages\" : [ {\"role\":\"user\", \"content\":[{\"text\":\"hi\"}]} ],\n \"zz\":1, \"aa\":2 }"
	nativeModel        = "amazon.nova-lite-v1:0"
)

func nativeForwardRequest(op, modelID, body string) *infracontext.RequestContext {
	return &infracontext.RequestContext{
		Body:            []byte(body),
		SourceFormat:    "bedrock_native",
		ProxyCapability: "bedrock_native",
		BedrockNative:   &infracontext.BedrockNativeTarget{Op: bedrocknative.Op(op), ModelID: modelID, RawModelID: modelID},
	}
}

var viewOf = adapter.BedrockFrameView

func nativeOKResponse() *appproxy.ProviderResponse {
	return &appproxy.ProviderResponse{
		StatusCode: http.StatusOK,
		Headers:    map[string][]string{"Content-Type": {"application/json"}},
		Body:       []byte(`{"output":{"message":{"role":"assistant","content":[{"text":"ok"}]}}}`),
	}
}

func nativePolicy(slug string) []*policy.Policy {
	return []*policy.Policy{{
		ID: ids.New[ids.PolicyKind](), Name: slug, Slug: slug, Enabled: true, Priority: 1,
	}}
}

func TestForward_NativeBedrock_RoutesOnlyToBedrockRegistries(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	bedrock := backendFor(gatewayID, "bedrock")
	rc := routableConsumerWith(gatewayID, openai, bedrock)
	// The OpenAI registry allows the model too: it must still never be tried.
	rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{
		openai.ID:  {Allowed: []string{nativeModel}},
		bedrock.ID: {Allowed: []string{"amazon.nova-*"}},
	}

	var seen *infracontext.RequestContext
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool { return bk.ID == bedrock.ID }), mock.Anything).
		Run(func(_ context.Context, _ *registrydomain.Registry, req *infracontext.RequestContext) { seen = req }).
		Return(nativeOKResponse(), nil).
		Once()

	res, err := newTestForwarder(t, invoker).Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   nativeForwardRequest("converse", nativeModel, nativeConverseBody),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.True(t, res.Upstream, "an unmodified upstream answer is marked so the handler leaves it alone")
	assert.Equal(t, nativeConverseBody, string(seen.Body), "no stage may touch the body")
	assert.Equal(t, nativeModel, seen.RequestedModel)
	assert.Equal(t, []string{"amazon.nova-*"}, seen.AllowedModels)
}

func TestForward_NativeBedrock_NoBedrockRegistry(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "openai"), backendFor(gatewayID, "anthropic"))

	_, err := newTestForwarder(t, proxymocks.NewProviderInvoker(t)).Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   nativeForwardRequest("converse", nativeModel, `{}`),
	})
	assert.ErrorIs(t, err, routingdomain.ErrNoRegistryServesModel)
}

func TestForward_NativeBedrock_ModelDeniedOnBedrockEvenIfAnotherProviderAllowsIt(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	bedrock := backendFor(gatewayID, "bedrock")
	rc := routableConsumerWith(gatewayID, openai, bedrock)
	rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{
		openai.ID:  {Allowed: []string{nativeModel}},
		bedrock.ID: {Allowed: []string{"anthropic.*"}},
	}

	_, err := newTestForwarder(t, proxymocks.NewProviderInvoker(t)).Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   nativeForwardRequest("converse", nativeModel, `{}`),
	})
	assert.ErrorIs(t, err, routingdomain.ErrModelDenied)
}

func TestForward_NativeBedrock_ModelIDsAreNeverRoutingSyntax(t *testing.T) {
	for _, id := range []string{"auto", "pool:fast", "AUTO"} {
		t.Run(id, func(t *testing.T) {
			gatewayID := ids.New[ids.GatewayKind]()
			bedrock := backendFor(gatewayID, "bedrock")
			rc := routableConsumerWith(gatewayID, bedrock)

			var seen *infracontext.RequestContext
			invoker := proxymocks.NewProviderInvoker(t)
			invoker.EXPECT().
				Invoke(mock.Anything, mock.Anything, mock.Anything).
				Run(func(_ context.Context, _ *registrydomain.Registry, req *infracontext.RequestContext) { seen = req }).
				Return(nativeOKResponse(), nil).
				Once()

			_, err := newTestForwarder(t, invoker).Forward(context.Background(), appproxy.ForwardInput{
				GatewayID: gatewayID,
				Consumer:  rc,
				Request:   nativeForwardRequest("converse", id, `{}`),
			})
			require.NoError(t, err)
			assert.Equal(t, id, seen.RequestedModel)
			assert.Equal(t, "{}", string(seen.Body))
		})
	}
}

func TestForward_NativeBedrock_FailsOverAcrossBedrockRegistries(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	first := backendFor(gatewayID, "bedrock")
	second := backendFor(gatewayID, "bedrock")
	rc := routableConsumerWith(gatewayID, first, second)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool { return bk.ID == first.ID }), mock.Anything).
		Return(&appproxy.ProviderResponse{StatusCode: http.StatusServiceUnavailable, Body: []byte(`{"message":"down"}`)}, nil).
		Once()
	invoker.EXPECT().
		Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool { return bk.ID == second.ID }), mock.Anything).
		Return(nativeOKResponse(), nil).
		Once()

	res, err := newTestForwarder(t, invoker).Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   nativeForwardRequest("invoke", nativeModel, `{"prompt":"hi"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestForward_NativeBedrock_AWSErrorsAreRelayedAsUpstream(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "bedrock"))
	const awsBody = `{"message":"Malformed input request"}`

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{
			StatusCode: http.StatusBadRequest,
			Headers:    map[string][]string{"X-Amzn-Errortype": {"ValidationException"}},
			Body:       []byte(awsBody),
		}, nil).
		Once()

	res, err := newTestForwarder(t, invoker).Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   nativeForwardRequest("converse", nativeModel, `{}`),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	assert.Equal(t, awsBody, string(res.Body))
	assert.Equal(t, []string{"ValidationException"}, res.Headers["X-Amzn-Errortype"])
	assert.True(t, res.Upstream, "AWS's own error must never be re-wrapped")
}

func TestForward_NativeBedrock_RefusesAmbiguousBodies(t *testing.T) {
	cases := map[string]struct{ op, body string }{
		"converse repeated key":      {"converse", `{"messages":[],"messages":[]}`},
		"converse case-folded key":   {"converse-stream", `{"messages":[],"Messages":[]}`},
		"converse not json":          {"converse", `{"messages":`},
		"invoke repeated key":        {"invoke", `{"prompt":"a","prompt":"b"}`},
		"invoke case-folded key":     {"invoke-with-response-stream", `{"prompt":"a","Prompt":"b"}`},
		"invoke nested repeated key": {"invoke", `{"textGenerationConfig":{"topP":1,"topP":2},"inputText":"x"}`},
		"invoke not json":            {"invoke", `not json`},
		"invoke byte order mark":     {"invoke", "\xef\xbb\xbf{\"prompt\":\"a\"}"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			gatewayID := ids.New[ids.GatewayKind]()
			rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "bedrock"))
			_, err := newTestForwarder(t, proxymocks.NewProviderInvoker(t)).Forward(context.Background(), appproxy.ForwardInput{
				GatewayID: gatewayID,
				Consumer:  rc,
				Request:   nativeForwardRequest(tc.op, nativeModel, tc.body),
			})
			assert.ErrorIs(t, err, appproxy.ErrAmbiguousRequestBody)
		})
	}

	t.Run("an empty body is left to AWS", func(t *testing.T) {
		gatewayID := ids.New[ids.GatewayKind]()
		rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "bedrock"))
		invoker := proxymocks.NewProviderInvoker(t)
		invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).Return(nativeOKResponse(), nil).Once()
		_, err := newTestForwarder(t, invoker).Forward(context.Background(), appproxy.ForwardInput{
			GatewayID: gatewayID, Consumer: rc, Request: nativeForwardRequest("converse", nativeModel, ``),
		})
		require.NoError(t, err)
	})
}

// A masking policy whose change is not a replacement of text cannot be carried onto
// the request: the call is refused, since the bytes the client sent are what the
// policy asked to mask, and the outcome is recorded as a blocked policy result.
func TestForward_NativeBedrock_RequestMaskThatCannotBeAppliedBlocks(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "bedrock"))
	rc.Policies = nativePolicy("regex_replace")

	invoker := proxymocks.NewProviderInvoker(t) // Invoke must never be called
	p := &stubPlugin{
		name:   "regex_replace",
		stages: []policy.Stage{policy.StagePreRequest},
		result: &appplugins.Result{StatusCode: http.StatusOK, RequestBody: []byte(`{"masked":true}`)},
	}

	ctx, rt := tracedContext()
	res, err := forwarderWithPlugin(t, invoker, maskStubPlugin{p}).Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   nativeForwardRequest("converse", nativeModel, nativeConverseBody),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
	assert.Contains(t, string(res.Body), "native_bedrock_passthrough")
	requireMaskBlocked(t, rt, "pre_request", "shape_mismatch")
}

func TestForward_NativeBedrock_RequestRewriteToIdenticalBytesIsNotABlock(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "bedrock"))
	rc.Policies = nativePolicy("regex_replace")

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).Return(nativeOKResponse(), nil).Once()
	p := &stubPlugin{
		name:   "regex_replace",
		stages: []policy.Stage{policy.StagePreRequest},
		result: &appplugins.Result{StatusCode: http.StatusOK, RequestBody: []byte(nativeConverseBody)},
	}

	res, err := forwarderWithPlugin(t, invoker, p).Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   nativeForwardRequest("converse", nativeModel, nativeConverseBody),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestForward_NativeBedrock_NonNativeRequestRewriteStillApplies(t *testing.T) {
	// The control: the same plugin on an ordinary request rewrites the body,
	// which is what proves the block above comes from the native guard.
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "openai"))
	rc.Policies = nativePolicy("regex_replace")

	var forwarded []byte
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ *registrydomain.Registry, req *infracontext.RequestContext) {
			forwarded = req.Body
		}).
		Return(nativeOKResponse(), nil).
		Once()
	p := &stubPlugin{
		name:   "regex_replace",
		stages: []policy.Stage{policy.StagePreRequest},
		result: &appplugins.Result{StatusCode: http.StatusOK, RequestBody: []byte(`{"masked":true}`)},
	}

	_, err := forwarderWithPlugin(t, invoker, p).Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Body: []byte(`{"model":"gpt-5"}`)},
	})
	require.NoError(t, err)
	assert.Equal(t, `{"masked":true}`, string(forwarded))
}

func TestForward_NativeBedrock_ShortCircuitIsNeverAnAnswer(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		wantStatus int
	}{
		{"a cached 200 becomes a 403 block", http.StatusOK, http.StatusForbidden},
		{"a denial keeps its status", http.StatusTooManyRequests, http.StatusTooManyRequests},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gatewayID := ids.New[ids.GatewayKind]()
			rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "bedrock"))
			rc.Policies = nativePolicy("semantic_cache")

			invoker := proxymocks.NewProviderInvoker(t)
			p := &stubPlugin{
				name:   "semantic_cache",
				stages: []policy.Stage{policy.StagePreRequest},
				result: &appplugins.Result{StatusCode: tc.status, StopUpstream: true, Body: []byte(`{"cached":"answer"}`)},
			}
			res, err := forwarderWithPlugin(t, invoker, p).Forward(context.Background(), appproxy.ForwardInput{
				GatewayID: gatewayID,
				Consumer:  rc,
				Request:   nativeForwardRequest("converse", nativeModel, nativeConverseBody),
			})
			require.NoError(t, err)
			assert.Equal(t, tc.wantStatus, res.StatusCode)
			assert.False(t, res.Upstream)
			if tc.status == http.StatusOK {
				assert.Contains(t, string(res.Body), "native_bedrock_passthrough")
				assert.NotContains(t, string(res.Body), "cached")
			}
		})
	}
}

// A masking policy's change to the response that is not a replacement of text
// refuses the response, recorded as a blocked policy result: AWS's answer carries
// what the policy asked to mask.
func TestForward_NativeBedrock_ResponseMaskThatCannotBeAppliedBlocks(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "bedrock"))
	rc.Policies = nativePolicy("trustguard")

	provider := nativeOKResponse()
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).Return(provider, nil).Once()
	p := &stubPlugin{
		name:   "trustguard",
		stages: []policy.Stage{policy.StagePreResponse},
		result: &appplugins.Result{StatusCode: http.StatusOK, StopUpstream: true, Body: []byte(`{"masked":"ok and more words"}`)},
	}

	ctx, rt := tracedContext()
	res, err := forwarderWithPlugin(t, invoker, maskStubPlugin{p}).Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   nativeForwardRequest("converse", nativeModel, nativeConverseBody),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
	assert.Contains(t, string(res.Body), "native_bedrock_passthrough")
	assert.NotContains(t, string(res.Body), string(provider.Body), "AWS's answer is not relayed")
	requireMaskBlocked(t, rt, "pre_response", "not_a_text_replacement")
}

// A policy that answers with a status of its own is answering for Bedrock, which
// is not a mask and is still refused.
func TestForward_NativeBedrock_ResponseWithAStatusOfItsOwnIsStillRefused(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "bedrock"))
	rc.Policies = nativePolicy("trustguard")

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).Return(nativeOKResponse(), nil).Once()
	p := &stubPlugin{
		name:   "trustguard",
		stages: []policy.Stage{policy.StagePreResponse},
		result: &appplugins.Result{StatusCode: http.StatusAccepted, StopUpstream: true, Body: []byte(`{"canned":true}`)},
	}

	ctx, rt := tracedContext()
	res, err := forwarderWithPlugin(t, invoker, p).Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   nativeForwardRequest("converse", nativeModel, nativeConverseBody),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
	assert.NotContains(t, string(res.Body), "canned")
	assert.Empty(t, maskBlockedEntries(rt), "this is a refusal of a rewrite, not a blocked mask")
}

func TestForward_NativeBedrock_ResponseLegThatKeepsTheBytesPasses(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "bedrock"))
	rc.Policies = nativePolicy("trustguard")

	provider := nativeOKResponse()
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).Return(provider, nil).Once()
	p := &stubPlugin{
		name:   "trustguard",
		stages: []policy.Stage{policy.StagePreResponse},
		result: &appplugins.Result{StatusCode: http.StatusOK},
	}

	res, err := forwarderWithPlugin(t, invoker, p).Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   nativeForwardRequest("converse", nativeModel, nativeConverseBody),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, string(provider.Body), string(res.Body))
	assert.True(t, res.Upstream)
}

func TestForward_NativeBedrock_PluginRejectionIsAGatewayError(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "bedrock"))
	rc.Policies = nativePolicy("trustguard")

	p := &stubPlugin{
		name:   "trustguard",
		stages: []policy.Stage{policy.StagePreRequest},
		err:    &appplugins.PluginError{StatusCode: http.StatusForbidden, Message: "blocked by policy"},
	}
	res, err := forwarderWithPlugin(t, proxymocks.NewProviderInvoker(t), p).Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   nativeForwardRequest("converse", nativeModel, nativeConverseBody),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
	assert.False(t, res.Upstream, "a block the gateway made is not AWS's, so the handler wraps it")
}

func TestForward_NativeBedrock_StreamRelaysFramesAndFeedsPostResponseTheView(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "bedrock"))
	rc.Policies = nativePolicy("token_rate_limiter")

	frames := [][]byte{
		nativeEvent(t, "contentBlockDelta", `{"contentBlockIndex":0,"delta":{"text":"Hello"}}`),
		nativeEvent(t, "messageStop", `{"stopReason":"end_turn"}`),
	}
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		InvokeStream(mock.Anything, mock.Anything, mock.Anything).
		Return(&appproxy.ProviderResponse{
			StatusCode: http.StatusOK,
			Headers:    map[string][]string{"Content-Type": {"application/vnd.amazon.eventstream"}},
			Stream:     nativeFrameSeq(frames...),
			RawFrames:  true,
			StreamView: viewOf,
		}, nil).
		Once()

	seen := make(chan appplugins.ExecInput, 1)
	p := &capturePlugin{
		name:   "token_rate_limiter",
		stages: []policy.Stage{policy.StagePreRequest, policy.StagePostResponse},
		seen:   seen,
	}
	res, err := forwarderWithPlugin(t, invoker, p).Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   nativeForwardRequest("converse-stream", nativeModel, `{"messages":[]}`),
	})
	require.NoError(t, err)
	require.NotNil(t, res.Stream)
	assert.True(t, res.RawFrames)
	assert.True(t, res.Upstream)
	require.NotNil(t, res.StreamView)

	var got [][]byte
	for frame, ferr := range res.Stream {
		require.NoError(t, ferr)
		got = append(got, frame)
	}
	assert.Equal(t, frames, got, "frames are relayed identical, with no line adaptation")

	select {
	case in := <-seen:
		assert.Equal(t,
			"data: {\"contentBlockDelta\":{\"contentBlockIndex\":0,\"delta\":{\"text\":\"Hello\"}}}\n"+
				"data: {\"messageStop\":{\"stopReason\":\"end_turn\"}}\n",
			string(in.Response.Body),
			"post_response must read the decoded view, not the binary frames")
	case <-time.After(2 * time.Second):
		t.Fatal("post_response never ran after the stream drained")
	}
}

func TestForward_NativeBedrock_RefusesInvalidText(t *testing.T) {
	cases := map[string]string{
		"invalid utf-8":       "{\"prompt\":\"\xff\xfe\"}",
		"lone high surrogate": `{"prompt":"\ud800"}`,
		"lone low surrogate":  `{"prompt":"x\udc00"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			gatewayID := ids.New[ids.GatewayKind]()
			rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "bedrock"))
			_, err := newTestForwarder(t, proxymocks.NewProviderInvoker(t)).Forward(context.Background(), appproxy.ForwardInput{
				GatewayID: gatewayID,
				Consumer:  rc,
				Request:   nativeForwardRequest("invoke", nativeModel, body),
			})
			assert.ErrorIs(t, err, appproxy.ErrInvalidRequestPayload)
		})
	}
}

const awsModelInvalidBody = `{"message":"The provided model identifier is invalid."}`

func awsModelInvalid(requestID string) *appproxy.ProviderResponse {
	return &appproxy.ProviderResponse{
		StatusCode: http.StatusBadRequest,
		Headers: map[string][]string{
			"Content-Type":     {"application/json"},
			"X-Amzn-Errortype": {"ValidationException:http://internal.amazon.com/coral/com.amazon.bedrock/"},
			"X-Amzn-Requestid": {requestID},
		},
		Body: []byte(awsModelInvalidBody),
	}
}

// AWS's answer to an unknown model reads as a model miss, so the next Bedrock
// registry is probed. When none has it, the caller gets AWS's last answer, not
// a gateway 404 its SDK cannot classify.
func TestForward_NativeBedrock_ModelMissRelaysTheLastAWSAnswer(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	first := backendFor(gatewayID, "bedrock")
	second := backendFor(gatewayID, "bedrock")
	rc := routableConsumerWith(gatewayID, first, second)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool { return bk.ID == first.ID }), mock.Anything).
		Return(awsModelInvalid("req-first"), nil).Once()
	invoker.EXPECT().
		Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool { return bk.ID == second.ID }), mock.Anything).
		Return(awsModelInvalid("req-last"), nil).Once()

	res, err := newTestForwarder(t, invoker).Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   nativeForwardRequest("converse", "no.such-model-v1:0", `{"messages":[]}`),
	})
	require.NoError(t, err, "a gateway 404 would come back as an error")
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	assert.Equal(t, awsModelInvalidBody, string(res.Body))
	assert.Equal(t, []string{"ValidationException:http://internal.amazon.com/coral/com.amazon.bedrock/"}, res.Headers["X-Amzn-Errortype"])
	assert.Equal(t, []string{"req-last"}, res.Headers["X-Amzn-Requestid"])
	assert.True(t, res.Upstream, "AWS's own error must not be wrapped by the handler")
}

func TestForward_NativeBedrock_ModelMissOnOneRegistryStillProbesTheNext(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	first := backendFor(gatewayID, "bedrock")
	second := backendFor(gatewayID, "bedrock")
	rc := routableConsumerWith(gatewayID, first, second)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool { return bk.ID == first.ID }), mock.Anything).
		Return(awsModelInvalid("req-first"), nil).Once()
	invoker.EXPECT().
		Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool { return bk.ID == second.ID }), mock.Anything).
		Return(nativeOKResponse(), nil).Once()

	res, err := newTestForwarder(t, invoker).Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   nativeForwardRequest("converse", nativeModel, `{"messages":[]}`),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestForward_ModelMissOnANonNativeRequestStillBecomesAGateway404(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "openai"))
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.Anything, mock.Anything).
		Return(awsModelInvalid("r"), nil).Once()

	_, err := newTestForwarder(t, invoker).Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   &infracontext.RequestContext{Body: []byte(`{"model":"gpt-x"}`)},
	})
	assert.ErrorIs(t, err, routingdomain.ErrNoRegistryServesModel)
}

const awsNoAccessBody = `{"message":"You don't have access to the model with the specified model ID."}`

func awsAccessDenied(requestID string) *appproxy.ProviderResponse {
	return &appproxy.ProviderResponse{
		StatusCode: http.StatusForbidden,
		Headers: map[string][]string{
			"X-Amzn-Errortype": {"AccessDeniedException:http://internal.amazon.com/coral/com.amazon.bedrock/"},
			"X-Amzn-Requestid": {requestID},
		},
		Body: []byte(awsNoAccessBody),
	}
}

// An account that has not enabled a model answers AccessDeniedException; another
// registry, with another account, may have it, so it is probed.
func TestForward_NativeBedrock_AccessDeniedOnOneAccountProbesTheNext(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	first := backendFor(gatewayID, "bedrock")
	second := backendFor(gatewayID, "bedrock")
	rc := routableConsumerWith(gatewayID, first, second)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().
		Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool { return bk.ID == first.ID }), mock.Anything).
		Return(awsAccessDenied("req-first"), nil).Once()
	invoker.EXPECT().
		Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool { return bk.ID == second.ID }), mock.Anything).
		Return(nativeOKResponse(), nil).Once()

	res, err := newTestForwarder(t, invoker).Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID, Consumer: rc, Request: nativeForwardRequest("converse", nativeModel, `{"messages":[]}`),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestForward_NativeBedrock_AccessDeniedEverywhereRelaysTheLastAWSAnswer(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	first := backendFor(gatewayID, "bedrock")
	second := backendFor(gatewayID, "bedrock")
	rc := routableConsumerWith(gatewayID, first, second)

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool { return bk.ID == first.ID }), mock.Anything).
		Return(awsAccessDenied("req-first"), nil).Once()
	invoker.EXPECT().Invoke(mock.Anything, mock.MatchedBy(func(bk *registrydomain.Registry) bool { return bk.ID == second.ID }), mock.Anything).
		Return(awsAccessDenied("req-last"), nil).Once()

	res, err := newTestForwarder(t, invoker).Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID, Consumer: rc, Request: nativeForwardRequest("converse", nativeModel, `{"messages":[]}`),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
	assert.Equal(t, awsNoAccessBody, string(res.Body))
	assert.Equal(t, []string{"req-last"}, res.Headers["X-Amzn-Requestid"])
	assert.True(t, res.Upstream)
}

func TestForward_AccessDeniedOnANonNativeRequestStaysTerminal(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	first := backendFor(gatewayID, "openai")
	second := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, first, second)
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).Return(awsAccessDenied("r"), nil).Once()

	res, err := newTestForwarder(t, invoker).Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID, Consumer: rc, Request: &infracontext.RequestContext{Body: []byte(`{"model":"gpt-x"}`)},
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, res.StatusCode, "no probing outside native calls")
}

// A text document the view cannot read is refused, never left out of the view
// silently: the model would read it and no policy would.
func TestForward_NativeBedrock_RefusesADocumentItCannotInspect(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString
	for name, body := range map[string]string{
		"not base64":     `{"messages":[{"role":"user","content":[{"document":{"format":"txt","name":"n","source":{"bytes":"@@@"}}}]}]}`,
		"not UTF-8 text": `{"messages":[{"role":"user","content":[{"document":{"format":"csv","name":"n","source":{"bytes":"` + enc([]byte{0xff, 0xfe, 'a'}) + `"}}}]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			gatewayID := ids.New[ids.GatewayKind]()
			rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "bedrock"))
			_, err := newTestForwarder(t, proxymocks.NewProviderInvoker(t)).Forward(context.Background(), appproxy.ForwardInput{
				GatewayID: gatewayID, Consumer: rc, Request: nativeForwardRequest("converse", nativeModel, body),
			})
			require.ErrorIs(t, err, appproxy.ErrInvalidRequestPayload)
			assert.Contains(t, err.Error(), "document could not be inspected")
		})
	}
}

// Bedrock reads content from S3 with the registry's credentials; no policy can see
// it, so a request that references it is refused.
func TestForward_NativeBedrock_RefusesContentReferencedFromS3(t *testing.T) {
	src := `"source":{"s3Location":{"uri":"s3://bucket/key"}}`
	for name, body := range map[string]string{
		"document": `{"messages":[{"role":"user","content":[{"document":{"format":"pdf","name":"n",` + src + `}}]}]}`,
		"image":    `{"messages":[{"role":"user","content":[{"image":{"format":"png",` + src + `}}]}]}`,
		"video":    `{"messages":[{"role":"user","content":[{"video":{"format":"mp4",` + src + `}}]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			gatewayID := ids.New[ids.GatewayKind]()
			rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "bedrock"))
			_, err := newTestForwarder(t, proxymocks.NewProviderInvoker(t)).Forward(context.Background(), appproxy.ForwardInput{
				GatewayID: gatewayID, Consumer: rc, Request: nativeForwardRequest("converse", nativeModel, body),
			})
			require.ErrorIs(t, err, appproxy.ErrInvalidRequestPayload)
			assert.Contains(t, err.Error(), "content referenced from S3 cannot be inspected")
		})
	}
}

// A mask that cannot be applied is refused, and so is a rewrite that is not a mask. A policy that rewrites a native call for enforcement
// (a tool filter, a per-tool limit that strips a tool) is not masking text: its
// change cannot be carried onto the client's bytes, and forwarding the original
// would let through exactly what it removed. The call is refused.
func TestForward_NativeBedrock_ARewriteThatIsNotAMaskBlocksTheRequest(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "bedrock"))
	rc.Policies = nativePolicy("tool_allowlist")

	invoker := proxymocks.NewProviderInvoker(t) // Invoke must never be called.
	// tool_allowlist stripping delete_db from the request's toolConfig.
	p := &stubPlugin{
		name:   "tool_allowlist",
		stages: []policy.Stage{policy.StagePreRequest},
		result: &appplugins.Result{StatusCode: http.StatusOK, RequestBody: []byte(nativeToolFilteredBody)},
	}

	ctx, rt := tracedContext()
	res, err := forwarderWithPlugin(t, invoker, p).Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   nativeForwardRequest("converse", nativeModel, nativeToolBody),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
	assert.False(t, res.Upstream)
	assert.Contains(t, string(res.Body), "native_bedrock_passthrough")
	assert.Empty(t, maskBlockedEntries(rt), "a refusal of a rewrite, not a blocked mask")
}

func TestForward_NativeBedrock_AResponseRewriteThatIsNotAMaskBlocksTheResponse(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "bedrock"))
	rc.Policies = nativePolicy("tool_allowlist")

	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).Return(nativeOKResponse(), nil).Once()
	p := &stubPlugin{
		name:   "tool_allowlist",
		stages: []policy.Stage{policy.StagePreResponse},
		result: &appplugins.Result{StatusCode: http.StatusOK, StopUpstream: true, Body: []byte(`{"output":{"message":{"role":"assistant","content":[{"text":"o"}]}}}`)},
	}

	ctx, rt := tracedContext()
	res, err := forwarderWithPlugin(t, invoker, p).Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID,
		Consumer:  rc,
		Request:   nativeForwardRequest("converse", nativeModel, nativeConverseBody),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
	assert.NotContains(t, string(res.Body), `"text":"o"`)
	assert.Empty(t, maskBlockedEntries(rt))
}

const (
	nativeToolBody = `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[` +
		`{"toolSpec":{"name":"search_docs","inputSchema":{"json":{"type":"object"}}}},` +
		`{"toolSpec":{"name":"delete_db","inputSchema":{"json":{"type":"object"}}}}]}}`
	nativeToolFilteredBody = `{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[` +
		`{"toolSpec":{"name":"search_docs","inputSchema":{"json":{"type":"object"}}}}]}}`
)

// A plugin that edits the request's body in place, without a result, is a rewrite
// too, and nobody declared it a mask: the call is refused, never forwarded.
func TestForward_NativeBedrock_ABodyEditedInPlaceByAPluginThatDoesNotMaskBlocks(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "bedrock"))
	rc.Policies = nativePolicy("tool_allowlist")
	invoker := proxymocks.NewProviderInvoker(t) // Invoke must never be called.
	p := &editInPlacePlugin{stubPlugin: &stubPlugin{name: "tool_allowlist", stages: []policy.Stage{policy.StagePreRequest},
		result: &appplugins.Result{StatusCode: http.StatusOK}}}

	res, err := forwarderWithPlugin(t, invoker, p).Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID, Consumer: rc, Request: nativeForwardRequest("converse", nativeModel, nativeToolBody),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
}

type editInPlacePlugin struct{ *stubPlugin }

func (p *editInPlacePlugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	in.Request.Body = []byte(nativeToolFilteredBody)
	return p.stubPlugin.Execute(ctx, in)
}
