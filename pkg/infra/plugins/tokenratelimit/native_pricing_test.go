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

package tokenratelimit

import (
	"context"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	systemProfileARN = "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-sonnet-4-5-20250929-v1:0"
	foundationARN    = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-4-5-20250929-v1:0"
	appProfileARN    = "arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/abc123xyz"
)

func nativeCostRequest(requested, resolved string) *infracontext.RequestContext {
	return &infracontext.RequestContext{
		Provider:       "bedrock",
		SourceFormat:   string(adapter.FormatBedrockNative),
		BedrockNative:  &infracontext.BedrockNativeTarget{Op: "converse", ModelID: requested, RawModelID: requested},
		RequestedModel: requested,
		ResolvedModel:  resolved,
		Metadata: map[string]interface{}{
			adapter.MetadataUsageKey: &adapter.CanonicalUsage{InputTokens: 10, OutputTokens: 0, TotalTokens: 10},
		},
	}
}

// A native call through an ARN must accrue against the model's price, or a
// dollar budget is bypassed by naming the model by ARN.
func TestPlugin_DollarBudget_NativeBedrockARNsArePriced(t *testing.T) {
	settings := map[string]any{
		"unit":          "dollars",
		"pricing_table": "custom",
		"custom_pricing": map[string]any{
			"anthropic.claude-sonnet-4-5*": map[string]any{"input": 0.001, "output": 0},
		},
		"aggregate": map[string]any{"max": 0.005, "time_window": "1m"},
	}
	cases := []struct {
		name      string
		requested string
		resolved  string
		trips     bool
	}{
		{"system profile ARN", systemProfileARN, "", true},
		{"foundation model ARN", foundationARN, "", true},
		{"application profile ARN resolved by the control plane", appProfileARN, "us.anthropic.claude-sonnet-4-5-20250929-v1:0", true},
		{"application profile ARN not resolved accrues zero, as any unpriced model", appProfileARN, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestPlugin(t)
			req := nativeCostRequest(tc.requested, tc.resolved)
			resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{}`)}

			_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, req, resp))
			require.NoError(t, err)

			_, err = p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
			if tc.trips {
				require.Error(t, err, "10 input tokens * $0.001 = $0.01 exceeds the $0.005 budget")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// The cost cap prices the call before it is forwarded. An application profile
// ARN that the forwarder resolved first is priced; one it could not stays an
// unknown model, with whatever unknown_model says.
func TestPlugin_CostCap_NativeBedrockOpaqueARN(t *testing.T) {
	settings := func(unknown string) map[string]any {
		return map[string]any{
			"pricing_table":  "custom",
			"custom_pricing": map[string]any{"anthropic.claude-sonnet-4-5*": map[string]any{"input": 0.000003, "output": 0.000015}},
			"cost_cap": map[string]any{
				"enabled":                       true,
				"max_input_cost_per_1k_tokens":  1,
				"max_output_cost_per_1k_tokens": 1,
				"unknown_model":                 unknown,
			},
		}
	}
	pre := func(req *infracontext.RequestContext, unknown string) error {
		_, err := newTestPlugin(t).Execute(context.Background(),
			input(policy.StagePreRequest, settings(unknown), req, &infracontext.ResponseContext{}))
		return err
	}

	t.Run("resolved before the pre_request stage: priced and allowed", func(t *testing.T) {
		require.NoError(t, pre(nativeCostRequest(appProfileARN, "us.anthropic.claude-sonnet-4-5-20250929-v1:0"), "reject"))
	})
	t.Run("not resolved: an unknown model, rejected by default", func(t *testing.T) {
		require.Error(t, pre(nativeCostRequest(appProfileARN, ""), "reject"))
	})
	t.Run("not resolved: pass_through still allows it", func(t *testing.T) {
		require.NoError(t, pre(nativeCostRequest(appProfileARN, ""), "pass_through"))
	})
}

// A per-user dollar budget (a personal key's own budget) counts a native Bedrock
// call too: the usage the invoker observed is read on the buffered leg, and a
// model named by ARN is priced through the model it resolves to. Without either,
// naming the model by ARN, or asking for InvokeModel, would spend nothing.
func TestPlugin_KeyDollarBudget_NativeBedrockIsCountedAndPriced(t *testing.T) {
	// A key-partitioned policy prices from the registry, not from custom pricing.
	settings := map[string]any{"partition": "key", "key_budgets": true, "unit": "dollars"}
	priced := func(requested, resolved string) *infracontext.RequestContext {
		req := nativeCostRequest(requested, resolved)
		req.RegistryPricing = &domain.Pricing{Overrides: map[string]domain.PriceOverride{
			"anthropic.claude-sonnet-4-5-20250929-v1:0": {Input: 0.001},
		}}
		return req
	}
	cases := []struct {
		name      string
		requested string
		resolved  string
		trips     bool
	}{
		{"system profile ARN", systemProfileARN, "", true},
		{"application profile ARN resolved by the control plane", appProfileARN, "us.anthropic.claude-sonnet-4-5-20250929-v1:0", true},
		{"application profile ARN not resolved is an unpriced model, which a hard budget refuses", appProfileARN, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestPlugin(t)
			alice := budgeted(aliceScope, unitDollars, 0.005, windowCalendarDay)
			req := priced(tc.requested, tc.resolved)
			resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{}`)}

			_, err := p.Execute(context.Background(), scopedInput(policy.StagePostResponse, settings, req, resp, alice))
			require.NoError(t, err)

			status := admit(p, settings, alice, priced(tc.requested, tc.resolved))
			if tc.trips {
				require.Equal(t, 429, status, "10 input tokens * $0.001 = $0.01 exceeds the key's $0.005")
			} else {
				require.Equal(t, 403, status, "never priced, so never admitted: the hard budget cannot be dodged by an ARN")
			}
		})
	}
}

// The model a native Bedrock call is counted against is the identifier in its
// path, even when it reads like a routing reference and even when the body carries
// a "model" field of its own, and a key-partitioned policy never swaps it for the
// registry's default.
func TestModelFor_NativeBedrockIsTheLiteralPathIdentifier(t *testing.T) {
	cfg := &config{Partition: partitionKey}
	for _, id := range []string{"pool:analytics", "auto", systemProfileARN} {
		req := nativeCostRequest(id, "")
		req.DefaultModel = "amazon.nova-lite-v1:0"
		req.Body = []byte(`{"model":"gpt-4o"}`)
		require.Equal(t, id, modelFor(cfg, req))
	}
}

// The model of a native Bedrock call is in its path, so a downgrade, which rewrites
// the model in the body, cannot be carried out on one: it is a refusal, before any
// budget is reserved. Forwarding the expensive model while the budget was charged
// the cheap price, with a downgrade header on the answer, would be a lie.
func TestPlugin_NativeBedrock_DowngradeRefusesInsteadOfRewriting(t *testing.T) {
	t.Run("cost cap", func(t *testing.T) {
		p := newTestPlugin(t)
		settings := map[string]any{
			"pricing_table": "custom",
			"custom_pricing": map[string]any{
				"anthropic.claude-sonnet-4-5*": map[string]any{"input": 0.001, "output": 0.002},
			},
			"cost_cap": map[string]any{
				"enabled":                      true,
				"max_input_cost_per_1k_tokens": 0.5,
				"behavior_on_violation":        "downgrade",
				"downgrade_to":                 "amazon.nova-lite-v1:0",
			},
		}
		req := nativeCostRequest("anthropic.claude-sonnet-4-5-20250929-v1:0", "")
		req.Body = []byte(`{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`)

		res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
		require.Error(t, err, "a native call is not downgraded")
		pe, ok := appplugins.AsPluginError(err)
		require.True(t, ok)
		assert.Equal(t, 403, pe.StatusCode)
		assert.Nil(t, res)
	})
	t.Run("budget", func(t *testing.T) {
		p := newTestPlugin(t)
		settings := map[string]any{
			"aggregate":            map[string]any{"max": 10, "time_window": "1m"},
			"behavior_on_exceeded": "downgrade_model",
			"downgrade_to":         "amazon.nova-lite-v1:0",
		}
		req := nativeCostRequest("anthropic.claude-sonnet-4-5-20250929-v1:0", "")
		req.Body = []byte(`{"messages":[{"role":"user","content":[{"text":"hi"}]}]}`)
		resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{}`)}
		_, err := p.Execute(context.Background(), input(policy.StagePostResponse, settings, req, resp))
		require.NoError(t, err)

		res, err := p.Execute(context.Background(), input(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}))
		require.Error(t, err, "the budget is spent and a native call cannot be downgraded")
		pe, ok := appplugins.AsPluginError(err)
		require.True(t, ok)
		assert.Equal(t, 429, pe.StatusCode)
		assert.Nil(t, res)
	})
}
