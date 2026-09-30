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

package pertoolratelimit

import (
	"context"
	"testing"
	"time"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type noPricing struct{}

func (noPricing) Resolve(context.Context, string, string) appcatalog.Pricing {
	return appcatalog.Pricing{}
}

func withSpan(in appplugins.ExecInput) (appplugins.ExecInput, *trace.RequestTrace, *trace.Span) {
	rt := trace.New("trace-skip", trace.Metadata{GatewayID: "gw-1"})
	span := rt.StartSpan(trace.SpanPlugin, PluginName)
	span.SetStage(string(in.Stage))
	span.SetStatusCode(200)
	in.Event = metrics.NewEventContext(span)
	return in, rt, span
}

func TestPlugin_PreRequest_RecordsSkippedWhenNothingToEvaluate(t *testing.T) {
	settings := ruleSettings("send_email", "reject_response", "1m", 5)
	tests := []struct {
		name   string
		req    *infracontext.RequestContext
		reason string
	}{
		{"llm request declares no tools", openAIReq(openAIReqBody(t)), skipReasonNoTools},
		{"llm request declares only unmatched tools", openAIReq(openAIReqBody(t, "lookup")), skipReasonNoMatchingRule},
		{"mcp call without a tool name", mcpReq([]byte(`{"arguments":{}}`)), skipReasonNoTools},
		{"mcp call to an unmatched tool", mcpReq(mcpBody(t, "lookup")), skipReasonNoMatchingRule},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := newPluginRedis(t)
			in, rt, span := withSpan(input(policy.StagePreRequest, settings, tc.req, nil))

			res, err := p.Execute(context.Background(), in)
			require.NoError(t, err)
			require.NotNil(t, res)

			extras, ok := span.PluginAttrsCopy().Extras.(skippedData)
			require.True(t, ok, "extras = %T", span.PluginAttrsCopy().Extras)
			assert.True(t, extras.Skipped)
			assert.Equal(t, tc.reason, extras.SkipReason)
			assert.Empty(t, span.PluginAttrsCopy().Decision, "a skip is neither allowed nor blocked")

			// The boundary: the metrics builder must keep the entry instead of
			// dropping it as a no-op span.
			evt := appmetrics.NewBuilder(adapter.NewRegistry(), noPricing{}).Build(
				context.Background(), rt,
				&infracontext.RequestContext{GatewayID: "gw-1", Method: "POST", Path: "/v1/chat/completions"},
				&infracontext.ResponseContext{StatusCode: 200},
				time.UnixMilli(1_000_000), time.UnixMilli(1_000_005),
			)
			require.Len(t, evt.PolicyChain, 1, "a skipped policy must survive into the chain")
			entry := evt.PolicyChain[0]
			assert.Equal(t, PluginName, entry.Name)
			assert.Empty(t, entry.Decision)
			assert.False(t, entry.Flagged)
			assert.Equal(t, map[string]any{
				"stage": "pre_request", "skipped": true, "skip_reason": tc.reason,
			}, entry.Extras)
		})
	}
}

func TestPlugin_PreRequest_MatchingToolIsNotSkipped(t *testing.T) {
	p, rdb := newPluginRedis(t)
	settings := ruleSettings("send_email", "reject_response", "1m", 5)
	seed(t, rdb, consumerKey("send_email", 0), 9)
	in, _, span := withSpan(input(policy.StagePreRequest, settings, openAIReq(openAIReqBody(t, "send_email")), nil))

	_, err := p.Execute(context.Background(), in)
	require.Error(t, err, "an exhausted tool is still refused")

	extras, ok := span.PluginAttrsCopy().Extras.(PerToolRateLimiterData)
	require.True(t, ok, "extras = %T", span.PluginAttrsCopy().Extras)
	assert.True(t, extras.LimitExceeded)

	mcpIn, _, mcpSpan := withSpan(input(policy.StagePreRequest, settings, mcpReq(mcpBody(t, "send_email")), nil))
	_, err = p.Execute(context.Background(), mcpIn)
	require.Error(t, err)
	_, isSkip := mcpSpan.PluginAttrsCopy().Extras.(skippedData)
	assert.False(t, isSkip)
}

func TestPlugin_PreRequest_ExecutedResultCountsNotSkipped(t *testing.T) {
	p, _ := newPluginRedis(t)
	settings := ruleSettings("send_email", "reject_response", "1m", 5)
	body := openAIToolResultsRaw(t, nil, []tcSpec{{"call_1", "send_email"}}, []string{"call_1"})
	in, _, span := withSpan(input(policy.StagePreRequest, settings, openAIReq(body), nil))

	_, err := p.Execute(context.Background(), in)
	require.NoError(t, err)

	_, isSkip := span.PluginAttrsCopy().Extras.(skippedData)
	assert.False(t, isSkip, "results the plugin counted mean it evaluated the request")
}

func (noPricing) InvalidateCache() {}
