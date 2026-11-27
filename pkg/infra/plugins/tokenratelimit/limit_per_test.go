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
	"net/http"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func limitPerSettings(extra map[string]any) map[string]any {
	s := map[string]any{"aggregate": map[string]any{"max": 100, "time_window": "1h"}}
	for k, v := range extra {
		s[k] = v
	}
	return s
}

func TestPlugin_LimitPer_CounterKeys(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	consumer := aliceScope
	consumer.Global = false
	noKey := appplugins.RuntimeScope{GatewayID: "gw-1", ConsumerID: "p-1", Global: true}
	model := `{"model":"@openai/gpt-6-luna"}`

	tests := []struct {
		name     string
		settings map[string]any
		scope    appplugins.RuntimeScope
		body     string
		wantKeys []string // empty: the request is not counted by this policy
	}{
		{"absent limit_per, global", limitPerSettings(nil), aliceScope, "", []string{"trl:tk-1:global:gw-1"}},
		{"absent limit_per, consumer", limitPerSettings(nil), consumer, "", []string{"trl:tk-1:consumer:p-1"}},
		{"shared equals absent", limitPerSettings(map[string]any{"limit_per": "shared"}), aliceScope, "", []string{"trl:tk-1:global:gw-1"}},
		{"partition key with shared keeps the key layout", limitPerSettings(map[string]any{"limit_per": "shared", "partition": "key"}), aliceScope, "", []string{"trl:tk-1:key:owner:alice"}},
		{"application without an application", limitPerSettings(map[string]any{"limit_per": "application"}), appplugins.RuntimeScope{GatewayID: "gw-1", Global: true}, "", nil},
		{"api_key equals the partition key", limitPerSettings(map[string]any{"limit_per": "api_key"}), aliceScope, "", []string{"trl:tk-1:key:owner:alice"}},
		{"api_key without a key is not counted", limitPerSettings(map[string]any{"limit_per": "api_key"}), noKey, "", nil},
		{"application on a global policy", limitPerSettings(map[string]any{"limit_per": "application"}), aliceScope, "", []string{"trl:tk-1:global:gw-1:app:p-1"}},
		{"application selected, in the list", limitPerSettings(map[string]any{"limit_per": "application", "applies_to": "selected", "selected": []string{"p-1"}}), aliceScope, "", []string{"trl:tk-1:global:gw-1:app:p-1"}},
		{"application selected, outside the list", limitPerSettings(map[string]any{"limit_per": "application", "applies_to": "selected", "selected": []string{"p-2"}}), aliceScope, "", nil},
		{"model", limitPerSettings(map[string]any{"limit_per": "model"}), aliceScope, model, []string{"trl:tk-1:global:gw-1:mdl:%40openai%2Fgpt-6-luna"}},
		{"model filter matches", limitPerSettings(map[string]any{"limit_per": "model", "models": []string{"@openai/*"}}), aliceScope, model, []string{"trl:tk-1:global:gw-1:mdl:%40openai%2Fgpt-6-luna"}},
		{"model filter misses", limitPerSettings(map[string]any{"limit_per": "model", "models": []string{"claude-*"}}), aliceScope, model, nil},
		{"a bare pattern matches the model on any provider", limitPerSettings(map[string]any{"limit_per": "model", "models": []string{"gpt-6-luna"}}), aliceScope, model, []string{"trl:tk-1:global:gw-1:mdl:%40openai%2Fgpt-6-luna"}},
		{"model not named counts against the policy's own counter", limitPerSettings(map[string]any{"limit_per": "model"}), aliceScope, "", []string{"trl:tk-1:global:gw-1"}},
		{"header through limit_per", limitPerSettings(map[string]any{"limit_per": "header", "group_by_header": "X-Team"}), consumer, "", []string{"trl:tk-1:consumer:p-1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, mr := newClockedPlugin(t, &now)
			spend(t, p, tt.settings, tt.scope, llmRequest(tt.body, nil), 10)
			assert.ElementsMatch(t, tt.wantKeys, mr.Keys())
		})
	}
}

func TestPlugin_LimitPer_ModelCountsEachModelSeparately(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPlugin(t, &now)
	settings := limitPerSettings(map[string]any{"limit_per": "model", "aggregate": map[string]any{"max": 50, "time_window": "1h"}})
	a, b := llmRequest(`{"model":"gpt-a"}`, nil), llmRequest(`{"model":"gpt-b"}`, nil)

	spend(t, p, settings, aliceScope, a, 50)
	assert.Equal(t, http.StatusTooManyRequests, admit(p, settings, aliceScope, a))
	assert.Equal(t, http.StatusOK, admit(p, settings, aliceScope, b), "another model has its own counter")
}

func TestPlugin_LimitPer_ApplicationCountsEachApplicationSeparately(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPlugin(t, &now)
	settings := limitPerSettings(map[string]any{"limit_per": "application", "aggregate": map[string]any{"max": 50, "time_window": "1h"}})
	other := aliceScope
	other.ConsumerID = "p-2"

	spend(t, p, settings, aliceScope, llmRequest("", nil), 50)
	assert.Equal(t, http.StatusTooManyRequests, admit(p, settings, aliceScope, llmRequest("", nil)))
	assert.Equal(t, http.StatusOK, admit(p, settings, other, llmRequest("", nil)))
}

func TestConfig_LimitPer_Validation(t *testing.T) {
	tests := []struct {
		name    string
		extra   map[string]any
		wantErr bool
	}{
		{"absent", nil, false},
		{"unknown", map[string]any{"limit_per": "user"}, true},
		{"group is not offered on the budget", map[string]any{"limit_per": "group"}, true},
		{"api_key", map[string]any{"limit_per": "api_key"}, false},
		{"api_key with partition key", map[string]any{"limit_per": "api_key", "partition": "key"}, false},
		{"shared with partition key", map[string]any{"limit_per": "shared", "partition": "key"}, false},
		{"applies_to all on api_key", map[string]any{"limit_per": "api_key", "applies_to": "all"}, false},
		{"application with partition key", map[string]any{"limit_per": "application", "partition": "key"}, true},
		{"model with partition key", map[string]any{"limit_per": "model", "partition": "key"}, true},
		{"api_key refuses group_by_header", map[string]any{"limit_per": "api_key", "group_by_header": "X-T"}, true},
		{"api_key refuses downgrade_model", map[string]any{"limit_per": "api_key", "behavior_on_exceeded": "downgrade_model", "downgrade_to": "m"}, true},
		{"application selected with a list", map[string]any{"limit_per": "application", "applies_to": "selected", "selected": []string{"a"}}, false},
		{"application selected with an empty list", map[string]any{"limit_per": "application", "applies_to": "selected", "selected": []string{}}, true},
		{"model filter", map[string]any{"limit_per": "model", "models": []string{"gpt-*"}}, false},
		{"models without model mode", map[string]any{"limit_per": "application", "models": []string{"gpt-*"}}, true},
		{"header without a name", map[string]any{"limit_per": "header"}, true},
		{"header with a name", map[string]any{"limit_per": "header", "group_by_header": "X-T"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConfig(limitPerSettings(tt.extra))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestPlugin_LimitPer_ModelCountsTheServedDefault(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	p, mr := newClockedPlugin(t, &now)
	req := llmRequest(`{}`, nil)
	req.DefaultModel = "gpt-default"

	spend(t, p, limitPerSettings(map[string]any{"limit_per": "model"}), aliceScope, req, 10)
	assert.Equal(t, []string{"trl:tk-1:global:gw-1:mdl:%40openai%2Fgpt-default"}, mr.Keys())
}

// A downgrade rewrites the body between the stages: the spend must land on the
// counter of the model the request was admitted under.
func TestPlugin_LimitPer_ModelSpendStaysOnTheAdmittedCounterAfterDowngrade(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	p, mr := newClockedPlugin(t, &now)
	settings := limitPerSettings(map[string]any{
		"limit_per":            "model",
		"behavior_on_exceeded": "downgrade_model",
		"downgrade_to":         "gpt-4o-mini",
	})
	req := llmRequest(`{}`, nil)
	req.DefaultModel = "gpt-4o"

	_, err := p.Execute(context.Background(), scopedInput(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}, aliceScope))
	require.NoError(t, err)
	req.Body = []byte(`{"model":"gpt-4o-mini"}`)
	spend(t, p, settings, aliceScope, req, 10)

	assert.Equal(t, []string{"trl:tk-1:global:gw-1:mdl:%40openai%2Fgpt-4o"}, mr.Keys())
}

func TestPlugin_LimitPer_ModelLessRequestStillMeetsTheAggregate(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPlugin(t, &now)
	settings := limitPerSettings(map[string]any{"limit_per": "model", "aggregate": map[string]any{"max": 50, "time_window": "1h"}})

	spend(t, p, settings, aliceScope, llmRequest(`{}`, nil), 60)

	assert.Equal(t, http.StatusTooManyRequests, admit(p, settings, aliceScope, llmRequest(`{}`, nil)))
}

func TestPlugin_LimitPer_AutoMeetsTheServedModelsRule(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPlugin(t, &now)
	settings := limitPerSettings(map[string]any{
		"limit_per": "model",
		"per_model": true,
		"rules":     []map[string]any{{"model": "gpt-default", "max": 50, "time_window": "1h"}},
	})
	auto := func() *infracontext.RequestContext {
		req := llmRequest(`{}`, nil)
		req.RequestedModel = "auto"
		req.DefaultModel = "gpt-default"
		return req
	}

	spend(t, p, settings, aliceScope, auto(), 60)

	assert.Equal(t, http.StatusTooManyRequests, admit(p, settings, aliceScope, auto()))
}
