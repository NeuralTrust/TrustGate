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
	"maps"
	"net/http"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func budgeted(scope appplugins.RuntimeScope, limit float64, window string) appplugins.RuntimeScope {
	scope.KeyBudget = &authdomain.KeyBudget{Max: limit, TimeWindow: window}
	return scope
}

func keyBudgetsOnly() map[string]any {
	return map[string]any{"partition": "key", "key_budgets": true}
}

// withKeyBudgets opts a partition key policy into key budgets.
func withKeyBudgets(settings map[string]any) map[string]any {
	settings["key_budgets"] = true
	return settings
}

func preRequestHeaders(t *testing.T, p *Plugin, settings map[string]any, scope appplugins.RuntimeScope) map[string][]string {
	t.Helper()
	res, err := p.Execute(context.Background(), scopedInput(policy.StagePreRequest, settings, llmRequest("", nil), &infracontext.ResponseContext{}, scope))
	require.NoError(t, err)
	return res.Headers
}

func TestPlugin_KeyBudget_OverridesTheAggregate(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	p, mr := newClockedPlugin(t, &now)
	settings := withKeyBudgets(keyBudget(windowCalendarMonth, 1000))
	alice := budgeted(aliceScope, 100, windowCalendarMonth)
	bob := aliceScope
	bob.AuthID, bob.OwnerID = "auth-2", "bob"

	assert.Equal(t, []string{"100"}, preRequestHeaders(t, p, settings, alice)["X-Ratelimit-Limit-Tokens"], "the key's budget is the limit")
	assert.Equal(t, []string{"1000"}, preRequestHeaders(t, p, settings, bob)["X-Ratelimit-Limit-Tokens"], "a key without a budget keeps the aggregate")

	spend(t, p, settings, alice, llmRequest("", nil), 100)
	spend(t, p, settings, bob, llmRequest("", nil), 100)
	assert.Equal(t, http.StatusTooManyRequests, admit(p, settings, alice, llmRequest("", nil)))
	assert.Equal(t, http.StatusOK, admit(p, settings, bob, llmRequest("", nil)))
	mr.CheckGet(t, "trl:tk-1:key:owner:alice:p:2026-10", "100")
	mr.CheckGet(t, "trl:tk-1:key:owner:bob:p:2026-10", "100")
}

func TestPlugin_KeyBudget_EnforcedWithoutAnAggregate(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		settings map[string]any
		max      float64
	}{
		"tokens":  {settings: keyBudgetsOnly(), max: 10},
		"dollars": {settings: map[string]any{"partition": "key", "key_budgets": true, "unit": "dollars"}, max: 0.005},
	} {
		t.Run(name, func(t *testing.T) {
			p, mr := newClockedPlugin(t, &now)
			settings := tc.settings
			alice := budgeted(aliceScope, tc.max, windowCalendarDay)
			req := registryPriced("gpt-4o-mini")

			require.Equal(t, http.StatusOK, admit(p, settings, alice, req))
			spend(t, p, settings, alice, req, 10)
			assert.Equal(t, http.StatusTooManyRequests, admit(p, settings, alice, req))
			assert.Equal(t, []string{"trl:tk-1:key:owner:alice:p:2026-10-02"}, mr.Keys())
		})
	}
}

func TestPlugin_KeyBudget_KeyWithoutBudgetIsNotCountedWithoutAnAggregate(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	for name, settings := range map[string]map[string]any{
		"tokens":  keyBudgetsOnly(),
		"dollars": {"partition": "key", "key_budgets": true, "unit": "dollars"},
	} {
		t.Run(name, func(t *testing.T) {
			p, mr := newClockedPlugin(t, &now)
			unpriced := llmRequest(`{"model":"gpt-unpriced"}`, nil)
			for range 3 {
				assert.Equal(t, keyOutcome{status: http.StatusOK}, execKey(context.Background(), t, p, policy.StagePreRequest, policy.ModeEnforce, settings, unpriced, &infracontext.ResponseContext{}))
				spend(t, p, settings, aliceScope, unpriced, 1000)
			}
			assert.Zero(t, mr.CommandCount(), "nothing is read or written for a key without a budget")
		})
	}
}

func TestPlugin_KeyBudget_WindowKeys(t *testing.T) {
	now := time.Date(2026, 10, 2, 18, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		window, counter, reset string
		ttl                    time.Duration
	}{
		{window: windowCalendarMonth, counter: "trl:tk-1:key:owner:alice:p:2026-10", ttl: 29*24*time.Hour + 6*time.Hour, reset: "2527200s"},
		{window: windowCalendarDay, counter: "trl:tk-1:key:owner:alice:p:2026-10-02", ttl: 6 * time.Hour, reset: "21600s"},
	} {
		t.Run(tt.window, func(t *testing.T) {
			p, mr := newClockedPlugin(t, &now)
			alice := budgeted(aliceScope, 1000, tt.window)

			spend(t, p, keyBudgetsOnly(), alice, llmRequest("", nil), 40)

			assert.Equal(t, []string{tt.counter}, mr.Keys())
			mr.CheckGet(t, tt.counter, "40")
			assert.Equal(t, tt.ttl, mr.TTL(tt.counter))
			assert.Equal(t, []string{tt.reset}, preRequestHeaders(t, p, keyBudgetsOnly(), alice)["X-Ratelimit-Reset-Tokens"])
		})
	}
}

func TestPlugin_KeyBudget_LeavesTheRulesAlone(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	p, mr := newClockedPlugin(t, &now)
	settings := map[string]any{"partition": "key", "key_budgets": true, "rules": []map[string]any{{"model": "gpt-5", "max": 50, "time_window": windowCalendarDay}}}
	alice := budgeted(aliceScope, 1000, windowCalendarMonth)
	gpt5, gpt4 := llmRequest(`{"model":"gpt-5"}`, nil), llmRequest(`{"model":"gpt-4o"}`, nil)

	spend(t, p, settings, alice, gpt5, 50)
	assert.Equal(t, http.StatusTooManyRequests, admit(p, settings, alice, gpt5), "the per-model rule still applies")
	assert.Equal(t, http.StatusOK, admit(p, settings, alice, gpt4), "the key budget is not reached")
	mr.CheckGet(t, "trl:tk-1:key:owner:alice:p:2026-10-02:model:gpt-5", "50")
	mr.CheckGet(t, "trl:tk-1:key:owner:alice:p:2026-10", "50")

	bob := aliceScope
	bob.AuthID, bob.OwnerID = "auth-2", "bob"
	spend(t, p, settings, bob, gpt5, 50)
	assert.Equal(t, http.StatusTooManyRequests, admit(p, settings, bob, gpt5), "a key without a budget keeps the rules")
	assert.False(t, mr.Exists("trl:tk-1:key:owner:bob:p:2026-10"), "and has no aggregate counter")
}

func TestPlugin_KeyBudget_HardLimits(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	dollars := map[string]any{"partition": "key", "key_budgets": true, "unit": "dollars"}
	alice := budgeted(aliceScope, 0.005, windowCalendarMonth)

	got := execKeyAs(context.Background(), t, newDownPlugin(t), alice, policy.StagePreRequest, policy.ModeEnforce, keyBudgetsOnly(), llmRequest("", nil), &infracontext.ResponseContext{})
	assert.Equal(t, keyOutcome{status: http.StatusServiceUnavailable, errType: budgetUnavailable, scope: partitionKey, decision: decisionFailedClosed, reason: string(appplugins.FailureCounterUnavailable), failure: "read_counter"}, got)

	got = execKeyAs(context.Background(), t, newTestPlugin(t), alice, policy.StagePreRequest, policy.ModeEnforce, dollars, llmRequest(`{"model":"gpt-unpriced"}`, nil), &infracontext.ResponseContext{})
	assert.Equal(t, keyOutcome{status: http.StatusForbidden, errType: modelUnpriced, scope: partitionKey, decision: "block"}, got)

	p, _ := newClockedPlugin(t, &now)
	spend(t, p, dollars, alice, registryPriced("gpt-4o-mini"), 10)
	got = execKeyAs(context.Background(), t, p, alice, policy.StagePreRequest, policy.ModeEnforce, dollars, registryPriced("gpt-4o-mini"), &infracontext.ResponseContext{})
	assert.Equal(t, keyOutcome{status: http.StatusTooManyRequests, errType: dollarBudgetExceeded, scope: partitionKey, decision: "block"}, got)
}

func TestPlugin_KeyBudget_IgnoredWithoutPartitionKey(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	p, mr := newClockedPlugin(t, &now)
	settings := map[string]any{"aggregate": map[string]any{"max": 1000, "time_window": "1h"}}
	consumer := budgeted(aliceScope, 1, windowCalendarDay)
	consumer.Global = false

	spend(t, p, settings, consumer, llmRequest("", nil), 10)
	assert.Equal(t, http.StatusOK, admit(p, settings, consumer, llmRequest("", nil)))
	assert.Equal(t, []string{"trl:tk-1:consumer:p-1"}, mr.Keys())
}

func TestPlugin_KeyBudget_NeverReachesTheSharedConfig(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPlugin(t, &now)
	settings := withKeyBudgets(keyBudget(windowCalendarMonth, 1000))
	pristine := maps.Clone(settings)
	pristineAggregate := maps.Clone(settings["aggregate"].(map[string]any))
	bob := aliceScope
	bob.AuthID, bob.OwnerID = "auth-2", "bob"

	spend(t, p, settings, budgeted(aliceScope, 5, windowCalendarDay), llmRequest("", nil), 5)
	assert.Equal(t, []string{"1000"}, preRequestHeaders(t, p, settings, bob)["X-Ratelimit-Limit-Tokens"], "the next key does not inherit the budget")
	assert.Equal(t, pristine, settings)
	assert.Equal(t, pristineAggregate, settings["aggregate"])

	cfg, err := parseConfig(settings)
	require.NoError(t, err)
	aggregate, before := cfg.Aggregate, *cfg.Aggregate
	scoped := cfg.forKey(&authdomain.KeyBudget{Max: 5, TimeWindow: windowCalendarDay})
	assert.NotSame(t, cfg, scoped)
	assert.Equal(t, &aggregateConfig{Max: 5, TimeWindow: windowCalendarDay}, scoped.Aggregate)
	assert.Same(t, aggregate, cfg.Aggregate)
	assert.Equal(t, before, *cfg.Aggregate)
	assert.Same(t, cfg, cfg.forKey(nil), "a key without a budget uses the parsed config as is")
	unpartitioned := &config{Aggregate: aggregate}
	assert.Same(t, unpartitioned, unpartitioned.forKey(&authdomain.KeyBudget{Max: 5, TimeWindow: windowCalendarDay}))
}

func TestPlugin_ValidateConfig_AggregateIsOptionalWithKeyBudgets(t *testing.T) {
	p := New(nil, nil, nil)
	require.NoError(t, p.ValidateConfig(keyBudgetsOnly()))
	require.NoError(t, p.ValidateConfig(map[string]any{"partition": "key", "key_budgets": true, "unit": "dollars"}))
	require.ErrorContains(t, p.ValidateConfig(map[string]any{"partition": "key", "unit": "dollars"}), "at least one of window, rules, aggregate, or cost_cap must be set",
		"a partition key policy that does not read key budgets still needs a limit of its own")
	require.ErrorContains(t, p.ValidateConfig(map[string]any{"key_budgets": true, "aggregate": map[string]any{"max": 10}}), "key_budgets requires partition key")
	require.ErrorContains(t, p.ValidateConfig(map[string]any{"unit": "dollars"}), "at least one of window, rules, aggregate, or cost_cap must be set",
		"without partition key a policy still needs a limit of its own")
	require.ErrorContains(t, p.ValidateConfig(map[string]any{"partition": "owner"}), "partition must be key")
}

func TestCalendarWindowsAreTheKeyBudgetWindows(t *testing.T) {
	for _, window := range []string{authdomain.BudgetWindowCalendarMonth, authdomain.BudgetWindowCalendarDay} {
		require.NoError(t, (authdomain.KeyBudget{Max: 1, TimeWindow: window}).Validate())
		assert.True(t, isCalendarWindow(window), window)
	}
}

// A tenant's own partition key policy does not opt in: a key budget meant for
// the console's dollar policy must not replace its limit, nor its unit.
func TestPlugin_KeyBudget_IgnoredByAPolicyThatDoesNotOptIn(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	p, mr := newClockedPlugin(t, &now)
	settings := keyBudget(windowCalendarMonth, 1000)
	alice := budgeted(aliceScope, 1, windowCalendarDay)

	assert.Equal(t, []string{"1000"}, preRequestHeaders(t, p, settings, alice)["X-Ratelimit-Limit-Tokens"])
	spend(t, p, settings, alice, llmRequest("", nil), 10)
	assert.Equal(t, http.StatusOK, admit(p, settings, alice, llmRequest("", nil)))
	mr.CheckGet(t, "trl:tk-1:key:owner:alice:p:2026-10", "10")
}
