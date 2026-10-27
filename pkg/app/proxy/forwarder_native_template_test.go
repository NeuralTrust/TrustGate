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
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/prompttemplate"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/regexreplace"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func templateForwarder(t *testing.T, invoker appproxy.ProviderInvoker) appproxy.Forwarder {
	t.Helper()
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(regexreplace.New(adapter.NewRegistry(), nil)))
	require.NoError(t, reg.Register(prompttemplate.New()))
	exec := appplugins.NewExecutor(reg, newTestLogger())
	return appproxy.NewForwarder(
		loadbalancer.NewBaseFactory(nil, nil, nil, nil, nil),
		newPermissiveCache(t), cache.NewTTLMapManager(time.Minute), invoker, exec, nil, approuting.NewResolver(), nil, nil, nil, newTestLogger(),
	)
}

func templatePolicy(optIn bool) *policy.Policy {
	return &policy.Policy{
		ID: ids.New[ids.PolicyKind](), Name: "template", Slug: "prompt_template", Enabled: true, Priority: 1,
		Mode: policy.ModeEnforce, Stages: []policy.Stage{policy.StagePreRequest},
		Settings: map[string]any{
			"apply_on_native_bedrock": optIn,
			"inject_templates":        []any{map[string]any{"id": "sys", "role": "system", "content": "Be brief."}},
		},
	}
}

func forwardNative(t *testing.T, op, body string, pols ...*policy.Policy) (*appproxy.ForwardResult, []byte, error) {
	t.Helper()
	gatewayID := ids.New[ids.GatewayKind]()
	bk := backendFor(gatewayID, "bedrock")
	var forwarded []byte
	invoker := proxymocks.NewProviderInvoker(t)
	invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).
		Run(func(_ context.Context, _ *registrydomain.Registry, req *infracontext.RequestContext) {
			forwarded = req.Body
		}).
		Return(nativeOKResponse(), nil).Maybe()
	rc := routableConsumerWith(gatewayID, bk)
	rc.Policies = pols
	res, err := templateForwarder(t, invoker).Forward(context.Background(), appproxy.ForwardInput{
		GatewayID: gatewayID, Consumer: rc, Request: nativeForwardRequest(op, nativeModel, body),
	})
	return res, forwarded, err
}

func TestForward_NativeTemplate_InjectsOnlyIntoTheFieldsItEdits(t *testing.T) {
	body := "{ \"messages\" : [{\"role\":\"user\",\"content\":[{\"text\":\"hi\"},{\"cachePoint\":{\"type\":\"default\"}}]}],\n \"inferenceConfig\": {\"maxTokens\": 10} }"
	res, forwarded, err := forwardNative(t, "converse", body, templatePolicy(true))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "{ \"messages\" : [{\"role\":\"user\",\"content\":[{\"text\":\"hi\"},{\"cachePoint\":{\"type\":\"default\"}}]}],\n \"inferenceConfig\": {\"maxTokens\": 10},\"system\":[{\"text\":\"Be brief.\"}] }",
		string(forwarded))
}

func TestForward_NativeTemplate_NotOptedInIsSkipped(t *testing.T) {
	body := `{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`
	res, forwarded, err := forwardNative(t, "converse", body, templatePolicy(false))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, body, string(forwarded))
}

func TestForward_NativeTemplate_MaskIsCarriedOntoTheInjectedBody(t *testing.T) {
	_, mask := maskConsumer(ids.New[ids.GatewayKind](), "request", policy.ModeEnforce, policy.StagePreRequest)
	mask.Priority = 2
	res, forwarded, err := forwardNative(t, "converse", nativeMaskBody(), templatePolicy(true), mask)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode, "%s", res.Body)
	assert.Contains(t, string(forwarded), `"system":[{"text":"Be brief."}]`)
	assert.NotContains(t, string(forwarded), maskedEmail)
	assert.Contains(t, string(forwarded), "<EMAIL>")
	assert.Contains(t, string(forwarded), `"cachePoint":{"type":"default"}`)
	assert.Contains(t, string(forwarded), `"n":[1e-7,9007199254740993]`, "numbers keep their literal form")
}

func TestForward_NativeTemplate_UnsupportedShapeIsRefused(t *testing.T) {
	res, forwarded, err := forwardNative(t, "invoke", `{"prompt":"<|begin_of_text|>hi","max_gen_len":5}`, templatePolicy(true))
	require.NoError(t, err)
	assert.Nil(t, forwarded, "nothing reaches Bedrock")
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	assert.Contains(t, string(res.Body), "unsupported_native_shape:prompt")
}
