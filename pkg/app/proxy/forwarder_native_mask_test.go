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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	proxymocks "github.com/NeuralTrust/TrustGate/pkg/app/proxy/mocks"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/regexreplace"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const maskedEmail = "john.doe@example.com"

func nativeMaskBody() string {
	doc := base64.StdEncoding.EncodeToString([]byte("notes: contact " + maskedEmail))
	return `{"messages":[{"role":"user","content":[{"text":"my email is ` + maskedEmail + `"},{"cachePoint":{"type":"default"}},` +
		`{"document":{"format":"txt","name":"for ` + maskedEmail + `","source":{"bytes":"` + doc + `"}}}]}],` +
		`"inferenceConfig":{"maxTokens":100,"temperature":0.1},` +
		`"additionalModelRequestFields":{"copy":"` + maskedEmail + `","n":[1e-7,9007199254740993]}}`
}

// maskForwarder wires the real regex_replace plugin, which re-encodes through the
// canonical model exactly as every masking plugin does.
func maskForwarder(t *testing.T, invoker appproxy.ProviderInvoker, opts ...appproxy.ForwarderOption) appproxy.Forwarder {
	t.Helper()
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(regexreplace.New(adapter.NewRegistry(), nil)))
	exec := appplugins.NewExecutor(reg, newTestLogger())
	return appproxy.NewForwarder(
		loadbalancer.NewBaseFactory(nil, nil, nil, nil, nil),
		newPermissiveCache(t), cache.NewTTLMapManager(time.Minute), invoker, exec, nil, approuting.NewResolver(), nil, nil, nil, newTestLogger(),
		opts...,
	)
}

func maskConsumer(gatewayID ids.GatewayID, target string, mode policy.Mode, stage policy.Stage) (*registrydomain.Registry, *policy.Policy) {
	return backendFor(gatewayID, "bedrock"), &policy.Policy{
		ID: ids.New[ids.PolicyKind](), Name: "mask", Slug: "regex_replace", Enabled: true, Priority: 1,
		Mode: mode, Stages: []policy.Stage{stage},
		Settings: map[string]any{
			"target": target,
			"rules":  []map[string]any{{"pattern": `[\w.]+@[\w.]+\.com`, "replacement": "<EMAIL>"}},
		},
	}
}

func forwardMask(t *testing.T, fwd appproxy.Forwarder, gatewayID ids.GatewayID, bk *registrydomain.Registry, pol *policy.Policy, body string) (*appproxy.ForwardResult, error) {
	t.Helper()
	rc := routableConsumerWith(gatewayID, bk)
	rc.Policies = []*policy.Policy{pol}
	return fwd.Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID, Consumer: rc, Request: nativeForwardRequest("converse", nativeModel, body),
	})
}

func TestForward_NativeMask_RequestIsMaskedOntoTheOriginalBytes(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk, pol := maskConsumer(gatewayID, "request", policy.ModeEnforce, policy.StagePreRequest)
	var forwarded []byte
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ *registrydomain.Registry, req *infracontext.RequestContext) {
			forwarded = req.Body
		}).
		Return(nativeOKResponse(), nil).Once()

	res, err := forwardMask(t, maskForwarder(t, invoker), gatewayID, bk, pol, nativeMaskBody())
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode, "a mask is forwarded, not blocked")

	assert.NotContains(t, string(forwarded), maskedEmail, "no copy of the original reaches Bedrock, in any field")
	assert.Contains(t, string(forwarded), "<EMAIL>")
	var tree map[string]any
	dec := json.NewDecoder(bytes.NewReader(forwarded))
	dec.UseNumber()
	require.NoError(t, dec.Decode(&tree))
	extra := tree["additionalModelRequestFields"].(map[string]any)
	assert.Equal(t, "<EMAIL>", extra["copy"], "an unmodelled copy is masked too")
	assert.Equal(t, []any{json.Number("1e-7"), json.Number("9007199254740993")}, extra["n"], "numbers keep their literal form")
	assert.Contains(t, string(forwarded), `"cachePoint":{"type":"default"}`, "fields nobody masked are kept")
}

func TestForward_NativeMask_NothingToMaskKeepsTheBytes(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk, pol := maskConsumer(gatewayID, "request", policy.ModeEnforce, policy.StagePreRequest)
	body := "{ \"messages\" : [{\"role\":\"user\",\"content\":[{\"text\":\"no personal data here\"}]}],\n \"zz\":1 }"
	var forwarded []byte
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ *registrydomain.Registry, req *infracontext.RequestContext) {
			forwarded = req.Body
		}).
		Return(nativeOKResponse(), nil).Once()

	_, err := forwardMask(t, maskForwarder(t, invoker), gatewayID, bk, pol, body)
	require.NoError(t, err)
	assert.Equal(t, body, string(forwarded), "a policy that finds nothing leaves the bytes exactly as sent")
}

func TestForward_NativeMask_ObserveForwardsTheOriginal(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk, pol := maskConsumer(gatewayID, "request", policy.ModeObserve, policy.StagePreRequest)
	var forwarded []byte
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ *registrydomain.Registry, req *infracontext.RequestContext) {
			forwarded = req.Body
		}).
		Return(nativeOKResponse(), nil).Once()

	_, err := forwardMask(t, maskForwarder(t, invoker), gatewayID, bk, pol, nativeMaskBody())
	require.NoError(t, err)
	assert.Equal(t, nativeMaskBody(), string(forwarded), "observe never masks")
}

// requireMaskRefused asserts a native call refused because its mask could not be
// applied: a 403 native_bedrock_passthrough naming the policy, with nothing of the
// masked value in it.
func requireMaskRefused(t *testing.T, res *appproxy.ForwardResult, err error) {
	t.Helper()
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
	assert.Contains(t, string(res.Body), "native_bedrock_passthrough")
	assert.Contains(t, string(res.Body), "regex_replace")
	assert.NotContains(t, string(res.Body), maskedEmail)
}

// If the patcher leaves one copy of the text a policy removed, the mask cannot be
// applied: the leak check decides masked-or-not, and neither a half mask nor the
// original reaches Bedrock. The call is refused and recorded as blocked.
func TestForward_NativeMask_BrokenPatcherBlocksTheCall(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk, pol := maskConsumer(gatewayID, "request", policy.ModeEnforce, policy.StagePreRequest)
	invoker := proxymocks.NewProviderInvoker(t) // Invoke must never be called
	leaky := adapter.NativeMasker{Patch: func(body []byte, subs []adapter.Substitution) ([]byte, error) {
		// A patcher that only masks the first copy and leaves the rest.
		first := subs[0]
		return bytes.Replace(body, []byte(first.From), []byte(first.To), 1), nil
	}}

	ctx, rt := tracedContext()
	rc := routableConsumerWith(gatewayID, bk)
	rc.Policies = []*policy.Policy{pol}
	res, err := maskForwarder(t, invoker, appproxy.WithNativeMasker(leaky)).Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID, Consumer: rc, Request: nativeForwardRequest("converse", nativeModel, nativeMaskBody()),
	})
	requireMaskRefused(t, res, err)
	requireMaskBlocked(t, rt, "pre_request", "shape_mismatch")
}

// A mask that would edit a signed thinking block cannot be applied, because the
// edit would invalidate the signature: the call is refused and the outcome is
// recorded with its cause.
func TestForward_NativeMask_SignedBlockBlocksTheCall(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk, pol := maskConsumer(gatewayID, "request", policy.ModeEnforce, policy.StagePreRequest)
	body := `{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[` +
		`{"role":"assistant","content":[{"type":"thinking","thinking":"mail ` + maskedEmail + `","signature":"EqQB"}]},` +
		`{"role":"user","content":[{"type":"text","text":"go"}]}]}`
	invoker := proxymocks.NewProviderInvoker(t) // Invoke must never be called
	ctx, rt := tracedContext()
	rc := routableConsumerWith(gatewayID, bk)
	rc.Policies = []*policy.Policy{pol}
	res, err := maskForwarder(t, invoker).Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID, Consumer: rc, Request: nativeForwardRequest("invoke", nativeModel, body),
	})
	requireMaskRefused(t, res, err)
	entries := maskBlockedEntries(rt)
	require.Len(t, entries, 1)
	assert.Contains(t, entries[0].FailureReason, "mask_not_applicable:")
}

// A patcher that fails outright refuses the call the same way, with its own cause.
func TestForward_NativeMask_PatchErrorsBlockWithTheirCause(t *testing.T) {
	for name, tc := range map[string]struct {
		patch func([]byte, []adapter.Substitution) ([]byte, error)
		cause string
	}{
		"patch error": {func([]byte, []adapter.Substitution) ([]byte, error) { return nil, assert.AnError }, "patch_failed"},
	} {
		t.Run(name, func(t *testing.T) {
			gatewayID := ids.New[ids.GatewayKind]()
			bk, pol := maskConsumer(gatewayID, "request", policy.ModeEnforce, policy.StagePreRequest)
			invoker := proxymocks.NewProviderInvoker(t) // Invoke must never be called
			ctx, rt := tracedContext()
			rc := routableConsumerWith(gatewayID, bk)
			rc.Policies = []*policy.Policy{pol}
			res, err := maskForwarder(t, invoker, appproxy.WithNativeMasker(adapter.NativeMasker{Patch: tc.patch})).Forward(ctx,
				appproxy.ForwardInput{GatewayID: gatewayID, Consumer: rc, Request: nativeForwardRequest("converse", nativeModel, nativeMaskBody())})
			requireMaskRefused(t, res, err)
			requireMaskBlocked(t, rt, "pre_request", tc.cause)
		})
	}
}

func TestForward_NativeMask_BufferedResponseIsMasked(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk, pol := maskConsumer(gatewayID, "response", policy.ModeEnforce, policy.StagePreResponse)
	provider := &appproxy.ProviderResponse{
		StatusCode: http.StatusOK,
		Headers:    map[string][]string{"Content-Type": {"application/json"}, "X-Amzn-Requestid": {"r-1"}},
		Body: []byte(`{"output":{"message":{"role":"assistant","content":[{"text":"write to ` + maskedEmail + `"}]}},"stopReason":"end_turn",` +
			`"usage":{"inputTokens":7,"outputTokens":3,"totalTokens":10},"metrics":{"latencyMs":1234}}`),
	}
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).Return(provider, nil).Once()

	res, err := forwardMask(t, maskForwarder(t, invoker), gatewayID, bk, pol, `{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode, "body: %s", res.Body)
	assert.NotContains(t, string(res.Body), maskedEmail)
	assert.Contains(t, string(res.Body), "write to <EMAIL>")
	assert.Contains(t, string(res.Body), `"latencyMs":1234`, "the rest of the answer is AWS's")
	assert.Equal(t, []string{"r-1"}, res.Headers["X-Amzn-Requestid"], "AWS headers are kept")
}

func TestForward_NativeMask_BufferedResponseBrokenPatcherBlocksTheResponse(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk, pol := maskConsumer(gatewayID, "response", policy.ModeEnforce, policy.StagePreResponse)
	provider := &appproxy.ProviderResponse{
		StatusCode: http.StatusOK,
		Body:       []byte(`{"output":{"message":{"role":"assistant","content":[{"text":"write to ` + maskedEmail + `"}]}},"x":"` + maskedEmail + `"}`),
	}
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).Return(provider, nil).Once()
	leaky := adapter.NativeMasker{Patch: func(body []byte, subs []adapter.Substitution) ([]byte, error) {
		return bytes.Replace(body, []byte(subs[0].From), []byte(subs[0].To), 1), nil
	}}

	ctx, rt := tracedContext()
	rc := routableConsumerWith(gatewayID, bk)
	rc.Policies = []*policy.Policy{pol}
	res, err := maskForwarder(t, invoker, appproxy.WithNativeMasker(leaky)).Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID, Consumer: rc, Request: nativeForwardRequest("converse", nativeModel, `{"messages":[]}`),
	})
	requireMaskRefused(t, res, err)
	requireMaskBlocked(t, rt, "pre_response", "shape_mismatch")
}

// A response that is an AWS error is never masked, and an error body typically
// echoes the input: whatever a policy made of it, the answer is refused rather than
// relayed with the value the policy asked to mask, and the outcome is recorded as
// blocked.
func TestForward_NativeMask_ErrorResponseBlocks(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "bedrock"))
	rc.Policies = nativePolicy("trustguard")
	provider := &appproxy.ProviderResponse{
		StatusCode: http.StatusBadRequest,
		Headers:    map[string][]string{"X-Amzn-Errortype": {"ValidationException"}},
		Body:       []byte(`{"message":"bad input ` + maskedEmail + `"}`),
	}
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).Return(provider, nil).Once()
	p := &stubPlugin{
		name:   "trustguard",
		stages: []policy.Stage{policy.StagePreResponse},
		result: &appplugins.Result{StatusCode: http.StatusOK, StopUpstream: true, Body: []byte(`{"message":"bad input <EMAIL>"}`)},
	}

	ctx, rt := tracedContext()
	res, err := forwarderWithPlugin(t, invoker, maskStubPlugin{p}).Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID, Consumer: rc, Request: nativeForwardRequest("converse", nativeModel, `{"messages":[]}`),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
	assert.NotContains(t, string(res.Body), maskedEmail)
	requireMaskBlocked(t, rt, "pre_response", "error_response")
}

func awsErrorProvider() *appproxy.ProviderResponse {
	return &appproxy.ProviderResponse{
		StatusCode: http.StatusBadRequest,
		Headers:    map[string][]string{"X-Amzn-Errortype": {"ValidationException"}},
		Body:       []byte(`{"message":"bad input ` + maskedEmail + `"}`),
	}
}

// regex_replace keeps the status of the answer it masks, the other maskers answer
// 200: either way an AWS error is refused, never relayed as it came.
func TestForward_NativeMask_ErrorResponseWithARealMaskerBlocks(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	bk, pol := maskConsumer(gatewayID, "response", policy.ModeEnforce, policy.StagePreResponse)
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).Return(awsErrorProvider(), nil).Once()
	rc := routableConsumerWith(gatewayID, bk)
	rc.Policies = []*policy.Policy{pol}
	ctx, rt := tracedContext()
	res, err := maskForwarder(t, invoker).Forward(ctx, appproxy.ForwardInput{
		GatewayID: gatewayID, Consumer: rc, Request: nativeForwardRequest("converse", nativeModel, `{"messages":[]}`),
	})
	requireMaskRefused(t, res, err)
	requireMaskBlocked(t, rt, "pre_response", "error_response")
}

// A policy that is not a masker and answers an error with a status of its own is
// still refused.
func TestForward_NativeMask_ErrorResponseStatusChangeWithoutAMaskIsRefused(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	rc := routableConsumerWith(gatewayID, backendFor(gatewayID, "bedrock"))
	rc.Policies = nativePolicy("some_inspector")
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).Return(awsErrorProvider(), nil).Once()
	p := &stubPlugin{
		name:   "some_inspector",
		stages: []policy.Stage{policy.StagePreResponse},
		result: &appplugins.Result{StatusCode: http.StatusOK, StopUpstream: true, Body: []byte(`{"message":"x"}`)},
	}
	res, err := forwarderWithPlugin(t, invoker, p).Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID, Consumer: rc, Request: nativeForwardRequest("converse", nativeModel, `{"messages":[]}`),
	})
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
}

// maskConsumerWith is maskConsumer for a policy with extra settings.
func maskConsumerWith(gatewayID ids.GatewayID, target string, mode policy.Mode, stage policy.Stage, extra map[string]any) (*registrydomain.Registry, *policy.Policy) {
	bk, pol := maskConsumer(gatewayID, target, mode, stage)
	for k, v := range extra {
		pol.Settings[k] = v
	}
	return bk, pol
}

// A client can deliberately make a mask impossible to apply: the value as a key of
// requestMetadata, which no mask may rewrite, leaves a copy of it in the call. The
// call is refused and recorded as blocked, whatever an on_mask_failure still stored
// on the policy says.
func TestForward_NativeMask_AMaskThatCannotBeAppliedBlocks(t *testing.T) {
	keyTrick := `{"messages":[{"role":"user","content":[{"text":"mail ` + maskedEmail + `"}]}],"requestMetadata":{"` + maskedEmail + `":"x"}}`
	signed := `{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[` +
		`{"role":"assistant","content":[{"type":"thinking","thinking":"mail ` + maskedEmail + `","signature":"EqQB"}]},` +
		`{"role":"user","content":[{"type":"text","text":"go"}]}]}`
	for name, body := range map[string]string{"the value as a metadata key (leak_remaining)": keyTrick, "a signed thinking block": signed} {
		for variant, extra := range map[string]map[string]any{"default": nil, "a stored on_mask_failure pass": {"on_mask_failure": "pass"}} {
			t.Run(name+"/"+variant, func(t *testing.T) {
				gatewayID := ids.New[ids.GatewayKind]()
				bk, pol := maskConsumerWith(gatewayID, "request", policy.ModeEnforce, policy.StagePreRequest, extra)
				invoker := proxymocks.NewProviderInvoker(t) // Invoke must never be called
				ctx, rt := tracedContext()
				rc := routableConsumerWith(gatewayID, bk)
				rc.Policies = []*policy.Policy{pol}
				res, err := maskForwarder(t, invoker).Forward(ctx, appproxy.ForwardInput{
					GatewayID: gatewayID, Consumer: rc, Request: nativeForwardRequest("invoke", nativeModel, body)})
				requireMaskRefused(t, res, err)
				entries := maskBlockedEntries(rt)
				require.Len(t, entries, 1)
				assert.Contains(t, entries[0].FailureReason, "mask_not_applicable:")
			})
		}
	}

	t.Run("a mask that can be applied is applied whatever the setting", func(t *testing.T) {
		gatewayID := ids.New[ids.GatewayKind]()
		bk, pol := maskConsumerWith(gatewayID, "request", policy.ModeEnforce, policy.StagePreRequest, map[string]any{"on_mask_failure": "block"})
		var forwarded []byte
		invoker := proxymocks.NewProviderInvoker(t)
		invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).
			Run(func(_ context.Context, _ *registrydomain.Registry, req *infracontext.RequestContext) {
				forwarded = req.Body
			}).
			Return(nativeOKResponse(), nil).Once()
		res, err := forwardMask(t, maskForwarder(t, invoker), gatewayID, bk, pol, nativeMaskBody())
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		assert.NotContains(t, string(forwarded), maskedEmail)
	})

	t.Run("the buffered response leg blocks too", func(t *testing.T) {
		gatewayID := ids.New[ids.GatewayKind]()
		bk, pol := maskConsumerWith(gatewayID, "response", policy.ModeEnforce, policy.StagePreResponse, map[string]any{"on_mask_failure": "block"})
		provider := &appproxy.ProviderResponse{
			StatusCode: http.StatusOK,
			Body:       []byte(`{"output":{"message":{"role":"assistant","content":[{"text":"write to ` + maskedEmail + `"}]}},"trace":{"` + maskedEmail + `":1}}`),
		}
		invoker := proxymocks.NewProviderInvoker(t)
		invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).Return(provider, nil).Once()
		ctx, rt := tracedContext()
		rc := routableConsumerWith(gatewayID, bk)
		rc.Policies = []*policy.Policy{pol}
		res, err := maskForwarder(t, invoker).Forward(ctx, appproxy.ForwardInput{
			GatewayID: gatewayID, Consumer: rc, Request: nativeForwardRequest("converse", nativeModel, `{"messages":[]}`),
		})
		requireMaskRefused(t, res, err)
		require.Len(t, maskBlockedEntries(rt), 1)
	})
}
