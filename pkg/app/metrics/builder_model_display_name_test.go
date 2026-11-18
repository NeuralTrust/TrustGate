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

package metrics

import (
	"context"
	"testing"
	"time"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const profileARN = "arn:aws:bedrock:eu-west-1:123456789012:application-inference-profile/abc123"

func bedrockRequest(labels map[string]string) *infracontext.RequestContext {
	return &infracontext.RequestContext{
		GatewayID:           "gw-1",
		Method:              "POST",
		Path:                "/v1/chat/completions",
		Body:                []byte(`{"model":"` + profileARN + `","messages":[]}`),
		SourceFormat:        string(adapter.FormatOpenAI),
		RequestedModel:      profileARN,
		RegistryModelLabels: labels,
	}
}

func buildDisplayName(t *testing.T, rt *trace.RequestTrace, req *infracontext.RequestContext) string {
	t.Helper()
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"id":"x","choices":[]}`)}
	evt := newBuilder(appcatalog.Pricing{}).Build(context.Background(), rt, req, resp, time.UnixMilli(1), time.UnixMilli(2))
	require.NotNil(t, evt)
	return evt.Request.ModelDisplayName
}

func TestBuilder_ModelDisplayName(t *testing.T) {
	tests := []struct {
		name  string
		spans []*trace.LLMAttrs
		req   *infracontext.RequestContext
		want  string
	}{
		{
			name: "sent ARN keeps its label after the provider resolves the model",
			spans: []*trace.LLMAttrs{{
				Provider:          "bedrock",
				Model:             "anthropic.claude-3-5-sonnet-20240620-v1:0",
				SentModel:         profileARN,
				Attempt:           1,
				Outcome:           "success",
				ServedModelLabels: map[string]string{profileARN: "Claude Sonnet (prod)"},
			}},
			req:  bedrockRequest(nil),
			want: "Claude Sonnet (prod)",
		},
		{
			name: "a plugin rewrite to an unlabelled model does not borrow the requested label",
			spans: []*trace.LLMAttrs{{
				Provider:          "bedrock",
				Model:             "anthropic.claude-3-haiku-20240307-v1:0",
				SentModel:         "anthropic.claude-3-haiku-20240307-v1:0",
				RequestedModel:    profileARN,
				Attempt:           1,
				Outcome:           "success",
				ServedModelLabels: map[string]string{profileARN: "Claude Sonnet (prod)"},
			}},
			req:  bedrockRequest(nil),
			want: "",
		},
		{
			name: "a plugin rewrite to a labelled model reports that model's label",
			spans: []*trace.LLMAttrs{{
				Provider:       "bedrock",
				Model:          "anthropic.claude-3-haiku-20240307-v1:0",
				SentModel:      "anthropic.claude-3-haiku-20240307-v1:0",
				RequestedModel: profileARN,
				Attempt:        1,
				Outcome:        "success",
				ServedModelLabels: map[string]string{
					profileARN:                               "Claude Sonnet (prod)",
					"anthropic.claude-3-haiku-20240307-v1:0": "Claude Haiku (cheap)",
				},
			}},
			req:  bedrockRequest(nil),
			want: "Claude Haiku (cheap)",
		},
		{
			name: "a provider-prefixed request still finds the label of the model it sent",
			spans: []*trace.LLMAttrs{{
				Provider:          "bedrock",
				Model:             "anthropic.claude-3-5-sonnet-20240620-v1:0",
				SentModel:         profileARN,
				RequestedModel:    "@bedrock/" + profileARN,
				Attempt:           1,
				Outcome:           "success",
				ServedModelLabels: map[string]string{profileARN: "Claude Sonnet (prod)"},
			}},
			req:  bedrockRequest(nil),
			want: "Claude Sonnet (prod)",
		},
		{
			name: "served model is the last candidate",
			spans: []*trace.LLMAttrs{{
				Provider:          "openai",
				Model:             "gpt-4o",
				Attempt:           1,
				Outcome:           "success",
				ServedModelLabels: map[string]string{"gpt-4o": "GPT-4o (EU)"},
			}},
			req:  bedrockRequest(nil),
			want: "GPT-4o (EU)",
		},
		{
			name: "fallback uses the labels of the registry that served",
			spans: []*trace.LLMAttrs{
				{
					Provider:          "bedrock",
					SentModel:         profileARN,
					Attempt:           1,
					Outcome:           "upstream_error",
					ServedModelLabels: map[string]string{profileARN: "Primary"},
				},
				{
					Provider:          "bedrock",
					Model:             "anthropic.claude-3-haiku-20240307-v1:0",
					SentModel:         "anthropic.claude-3-haiku-20240307-v1:0",
					Attempt:           2,
					Fallback:          true,
					Outcome:           "success",
					ServedModelLabels: map[string]string{"anthropic.claude-3-haiku-20240307-v1:0": "Haiku fallback"},
				},
			},
			req:  bedrockRequest(map[string]string{profileARN: "Primary"}),
			want: "Haiku fallback",
		},
		{
			name: "fallback registry without labels shows no name",
			spans: []*trace.LLMAttrs{
				{
					Provider:          "bedrock",
					SentModel:         profileARN,
					Attempt:           1,
					Outcome:           "upstream_error",
					ServedModelLabels: map[string]string{profileARN: "Primary"},
				},
				{
					Provider:  "openai",
					Model:     "gpt-4o",
					SentModel: "gpt-4o",
					Attempt:   2,
					Fallback:  true,
					Outcome:   "success",
				},
			},
			req:  bedrockRequest(map[string]string{profileARN: "Primary"}),
			want: "",
		},
		{
			name: "no attempt falls back to the targeted registry",
			req:  bedrockRequest(map[string]string{profileARN: "Claude Sonnet (prod)"}),
			want: "Claude Sonnet (prod)",
		},
		{
			name: "no label leaves the name empty",
			spans: []*trace.LLMAttrs{{
				Provider:  "bedrock",
				SentModel: profileARN,
				Attempt:   1,
				Outcome:   "success",
			}},
			req:  bedrockRequest(nil),
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := trace.New("trace-display-name", trace.Metadata{GatewayID: "gw-1"})
			for _, attrs := range tt.spans {
				_ = rt.AddSpan(llmSpan(attrs.Provider, attrs, 200, 100*time.Millisecond, ""))
			}
			assert.Equal(t, tt.want, buildDisplayName(t, rt, tt.req))
		})
	}
}

func TestBuilder_ModelDisplayNameIsIndependentOfPricing(t *testing.T) {
	rt := trace.New("trace-display-name-price", trace.Metadata{GatewayID: "gw-1"})
	_ = rt.AddSpan(llmSpan("bedrock", &trace.LLMAttrs{
		Provider:          "bedrock",
		Model:             "anthropic.claude-3-5-sonnet-20240620-v1:0",
		SentModel:         profileARN,
		Attempt:           1,
		Outcome:           "success",
		Usage:             &adapter.CanonicalUsage{InputTokens: 10, OutputTokens: 5, TotalTokens: 15},
		ServedModelLabels: map[string]string{profileARN: "Claude Sonnet (prod)"},
	}, 200, 100*time.Millisecond, ""))
	resp := &infracontext.ResponseContext{StatusCode: 200, Body: []byte(`{"id":"x","choices":[]}`)}

	evt := newBuilder(appcatalog.Pricing{Found: true, InputPrice: 0.000003, OutputPrice: 0.000015, ModelLabel: "default"}).
		Build(context.Background(), rt, bedrockRequest(nil), resp, time.UnixMilli(1), time.UnixMilli(2))

	require.NotNil(t, evt.Cost)
	assert.Equal(t, "Claude Sonnet (prod)", evt.Request.ModelDisplayName)
	assert.Equal(t, "default", evt.Request.ModelLabel)
}
