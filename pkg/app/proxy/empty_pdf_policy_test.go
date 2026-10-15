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
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/regexreplace"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/toolinjection"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// qaEmptyPDFBody is the chat completion QA sends: an OpenAI file part whose
// file_data is a base64 data URL with an empty payload.
func qaEmptyPDFBody(stream bool) []byte {
	flag := "false"
	if stream {
		flag = "true"
	}
	return []byte(`{"model":"gpt-4.1-nano","max_tokens":40,"stream":` + flag + `,"messages":[{"role":"user","content":[{"type":"text","text":"Summarise the attached file in 5 words."},{"type":"file","file":{"filename":"j.pdf","file_data":"data:application/pdf;base64,"}}]}]}`)
}

// TestForward_EmptyPDFFilePartWithPoliciesRelaysUpstream400 is the guarded
// path for an empty PDF file part. A policy that re-encodes the chat body
// (data masking when a rule matches, tool injection always) used to fail the
// encode of that file and return the error unclassified, which the proxy
// reports as 502 backend_error before the provider is called. The request
// must reach the provider and relay its 400, for a buffered call and for a
// stream (the failure is before any SSE bytes).
func TestForward_EmptyPDFFilePartWithPoliciesRelaysUpstream400(t *testing.T) {
	upstream := []byte(`{"error":{"message":"Invalid file.","type":"invalid_request_error","param":null,"code":null}}`)
	for _, stream := range []bool{false, true} {
		name := "buffered"
		if stream {
			name = "stream"
		}
		t.Run(name, func(t *testing.T) {
			gatewayID := ids.New[ids.GatewayKind]()
			bk := backendFor(gatewayID, "openai")
			rc := routableConsumerWith(gatewayID, bk)
			rc.Policies = emptyPDFPolicies()

			var sent []byte
			invoker := proxymocks.NewProviderInvoker(t)
			capture := func(_ context.Context, _ *registrydomain.Registry, req *infracontext.RequestContext) (*appproxy.ProviderResponse, error) {
				sent = append([]byte(nil), req.Body...)
				return &appproxy.ProviderResponse{StatusCode: http.StatusBadRequest, Body: upstream}, nil
			}
			if stream {
				invoker.EXPECT().InvokeStream(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(capture).Once()
			} else {
				invoker.EXPECT().Invoke(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(capture).Once()
			}

			res, err := forwarderWithMaskAndInjection(t, invoker).Forward(context.Background(), appproxy.ForwardInput{
				GatewayID: gatewayID,
				Consumer:  rc,
				Request: &infracontext.RequestContext{
					SourceFormat: string(adapter.FormatOpenAI),
					Body:         qaEmptyPDFBody(stream),
				},
			})
			require.NoError(t, err)
			require.NotNil(t, res)
			assert.Equal(t, http.StatusBadRequest, res.StatusCode)
			assert.JSONEq(t, string(upstream), string(res.Body))
			assert.Contains(t, string(sent), `"file_data":"data:application/pdf;base64,"`)
			assert.Contains(t, string(sent), "Summary")
			assert.Contains(t, string(sent), "safety_check")
			assert.NotContains(t, string(sent), "Summarise")
		})
	}
}

func emptyPDFPolicies() []*policy.Policy {
	return []*policy.Policy{
		{
			ID: ids.New[ids.PolicyKind](), Name: "mask", Slug: "regex_replace", Enabled: true,
			Priority: 1, Mode: policy.ModeEnforce, Stages: []policy.Stage{policy.StagePreRequest},
			Settings: map[string]any{
				"target": "request",
				"rules":  []any{map[string]any{"pattern": "Summarise", "replacement": "Summary"}},
			},
		},
		{
			ID: ids.New[ids.PolicyKind](), Name: "inject", Slug: "tool_injection", Enabled: true,
			Priority: 2, Mode: policy.ModeEnforce,
			Settings: map[string]any{
				"inject_tools": []any{map[string]any{
					"type": "function",
					"function": map[string]any{
						"name": "safety_check", "description": "check",
						"parameters": map[string]any{"type": "object"},
					},
				}},
			},
		},
	}
}

func forwarderWithMaskAndInjection(t *testing.T, invoker appproxy.ProviderInvoker) appproxy.Forwarder {
	t.Helper()
	reg := adapter.NewRegistry()
	plugins := appplugins.NewRegistry()
	require.NoError(t, plugins.Register(regexreplace.New(reg, newTestLogger())))
	require.NoError(t, plugins.Register(toolinjection.New(reg)))
	exec := appplugins.NewExecutor(plugins, newTestLogger())
	mgr := cache.NewTTLMapManager(time.Minute)
	return appproxy.NewForwarder(
		loadbalancer.NewBaseFactory(nil, nil, nil, nil, nil),
		newPermissiveCache(t), mgr, invoker, exec, nil, approuting.NewResolver(), nil, nil, nil, newTestLogger(),
	)
}
