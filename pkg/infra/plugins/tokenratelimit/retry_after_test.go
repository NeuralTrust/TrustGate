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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	keygroupdomain "github.com/NeuralTrust/TrustGate/pkg/domain/keygroup"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var consumerBudgetScope = appplugins.RuntimeScope{ConsumerID: "c-1", GatewayID: "gw-1"}

// refusal runs the pre-request gate and returns the 429 it must answer.
func refusal(t *testing.T, p *Plugin, settings map[string]any, scope appplugins.RuntimeScope, req *infracontext.RequestContext) *appplugins.PluginError {
	t.Helper()
	_, err := p.Execute(context.Background(), scopedInput(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}, scope))
	require.Error(t, err)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	require.Equal(t, http.StatusTooManyRequests, pe.StatusCode)
	return pe
}

// The 429 tells the client when the window resets, rounded up so that waiting
// the advertised time always lands in the next window.
func TestBudget429_CarriesRetryAfter(t *testing.T) {
	modelA := llmRequest(`{"model":"model-a"}`, nil)
	tests := []struct {
		name     string
		settings map[string]any
		scope    appplugins.RuntimeScope
		req      *infracontext.RequestContext
		tokens   int
		elapsed  time.Duration
		want     string
	}{
		{
			name:     "tokens aggregate",
			settings: map[string]any{"aggregate": map[string]any{"max": 100, "time_window": "10m"}},
			scope:    consumerBudgetScope, req: llmRequest("", nil), tokens: 100,
			want: "600",
		},
		{
			name:     "tokens aggregate after part of the window",
			settings: map[string]any{"aggregate": map[string]any{"max": 100, "time_window": "10m"}},
			scope:    consumerBudgetScope, req: llmRequest("", nil), tokens: 100, elapsed: 90 * time.Second,
			want: "510",
		},
		{
			name:     "a fraction of a second rounds up",
			settings: map[string]any{"aggregate": map[string]any{"max": 100, "time_window": "10m"}},
			scope:    consumerBudgetScope, req: llmRequest("", nil), tokens: 100, elapsed: 90*time.Second + 500*time.Millisecond,
			want: "510",
		},
		{
			name:     "less than a second left is one second",
			settings: map[string]any{"aggregate": map[string]any{"max": 100, "time_window": "10s"}},
			scope:    consumerBudgetScope, req: llmRequest("", nil), tokens: 100, elapsed: 9900 * time.Millisecond,
			want: "1",
		},
		{
			name: "per-model rule",
			settings: map[string]any{"per_model": true, "rules": []map[string]any{
				{"model": "model-a", "max": 100, "time_window": "1h"},
			}},
			scope: consumerBudgetScope, req: modelA, tokens: 100,
			want: "3600",
		},
		{
			name:     "legacy window block",
			settings: map[string]any{"window": map[string]any{"unit": "minute", "max": 100}},
			scope:    consumerBudgetScope, req: llmRequest("", nil), tokens: 100,
			want: "60",
		},
		{
			name:     "dollars on a key partition",
			settings: keyDollarBudget(0.005),
			scope:    aliceScope, req: registryPriced("gpt-4o-mini"), tokens: 10,
			want: "86400",
		},
		{
			name:     "key budget",
			settings: keyBudgetsOnly(),
			scope:    budgeted(aliceScope, unitTokens, 100, windowCalendarDay), req: llmRequest("", nil), tokens: 100,
			want: "43200",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
			p, mr := newClockedPlugin(t, &now)
			spend(t, p, tt.settings, tt.scope, tt.req, tt.tokens)
			mr.FastForward(tt.elapsed)
			now = now.Add(tt.elapsed)

			pe := refusal(t, p, tt.settings, tt.scope, tt.req)

			assert.Equal(t, []string{tt.want}, pe.Headers["Retry-After"])
			reset := pe.Headers["X-Budget-Reset"]
			if reset == nil {
				reset = pe.Headers["X-Ratelimit-Reset-Tokens"]
			}
			require.NotNil(t, reset, "the existing reset header stays")
		})
	}
}

func TestBudget429_DowngradeThatCannotApplyStillCarriesRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPlugin(t, &now)
	settings := map[string]any{
		"aggregate":            map[string]any{"max": 100, "time_window": "1h"},
		"behavior_on_exceeded": "downgrade_model",
		"downgrade_to":         "@anthropic/claude-3-haiku",
	}
	req := llmRequest(`{"model":"gpt-4o"}`, nil)
	spend(t, p, settings, consumerBudgetScope, req, 100)

	pe := refusal(t, p, settings, consumerBudgetScope, req)

	assert.Equal(t, []string{"3600"}, pe.Headers["Retry-After"])
}

func TestBudgetDowngrade_DoesNotAnswer429OrRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPlugin(t, &now)
	settings := map[string]any{
		"aggregate":            map[string]any{"max": 100, "time_window": "1h"},
		"behavior_on_exceeded": "downgrade_model",
		"downgrade_to":         "gpt-4o-mini",
	}
	req := llmRequest(`{"model":"gpt-4o"}`, nil)
	spend(t, p, settings, consumerBudgetScope, req, 100)

	res, err := p.Execute(context.Background(), scopedInput(policy.StagePreRequest, settings, req, &infracontext.ResponseContext{}, consumerBudgetScope))

	require.NoError(t, err)
	assert.Empty(t, res.Headers["Retry-After"])
}

func TestGroupBudget429_CarriesRetryAfterUntilTheMonthEnds(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	g, _ := newClockedGroupBudget(t, &now, nil)
	b := groupLimits(t, usdLimit(1), nil, nil, keygroupdomain.ActionBlock)
	alice := groupKey("alice", b)
	spendGroup(t, g, alice, 1000)

	_, pe := admitGroup(t, g, alice)

	require.NotNil(t, pe)
	want := strconv.Itoa(int(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).Sub(now).Seconds()))
	assert.Equal(t, []string{want}, pe.Headers["Retry-After"])
	assert.Equal(t, []string{want + "s"}, pe.Headers["X-Budget-Reset"])
}

// A counter created in the last seconds of a period is stored for a minimum
// time so a stream ending later is still charged, but the client must be told
// when the period really ends.
func TestBudget429_CalendarRetryAfterIsThePeriodEnd(t *testing.T) {
	tests := []struct {
		name string
		now  time.Time
		want string
	}{
		{name: "mid day", now: time.Date(2026, 10, 2, 18, 0, 0, 0, time.UTC), want: "21600"},
		{name: "last seconds are not stretched to the storage floor", now: time.Date(2026, 10, 2, 23, 59, 30, 0, time.UTC), want: "30"},
		{name: "a fraction rounds up", now: time.Date(2026, 10, 2, 23, 59, 59, 500_000_000, time.UTC), want: "1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := tt.now
			p, _ := newClockedPlugin(t, &now)
			settings := keyBudget(windowCalendarDay, 100)
			spend(t, p, settings, aliceScope, llmRequest("", nil), 100)

			pe := refusal(t, p, settings, aliceScope, llmRequest("", nil))

			assert.Equal(t, []string{tt.want}, pe.Headers["Retry-After"])
		})
	}
}

// Calendar windows are not tied to a partition key: an aggregate or a per-model
// rule counted per consumer resets at the start of the UTC month or day.
func TestCalendarWindows_WithoutPartitionKey(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		settings  map[string]any
		req       *infracontext.RequestContext
		counter   string
		wantReset string
	}{
		{
			name:      "aggregate month",
			settings:  map[string]any{"aggregate": map[string]any{"max": 100, "time_window": "calendar_month"}},
			req:       llmRequest("", nil),
			counter:   "trl:tk-1:consumer:c-1:p:2026-10",
			wantReset: strconv.Itoa(int(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).Sub(now).Seconds())),
		},
		{
			name:      "aggregate day",
			settings:  map[string]any{"aggregate": map[string]any{"max": 100, "time_window": "calendar_day"}},
			req:       llmRequest("", nil),
			counter:   "trl:tk-1:consumer:c-1:p:2026-10-02",
			wantReset: "43200",
		},
		{
			name: "per-model rule month",
			settings: map[string]any{"per_model": true, "rules": []map[string]any{
				{"model": "model-a", "max": 100, "time_window": "calendar_month"},
			}},
			req:       llmRequest(`{"model":"model-a"}`, nil),
			counter:   "trl:tk-1:consumer:c-1:p:2026-10:model:model-a",
			wantReset: strconv.Itoa(int(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).Sub(now).Seconds())),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := now
			p, mr := newClockedPlugin(t, &clock)
			require.NoError(t, p.ValidateConfig(tt.settings))

			spend(t, p, tt.settings, consumerBudgetScope, tt.req, 100)
			mr.CheckGet(t, tt.counter, "100")

			pe := refusal(t, p, tt.settings, consumerBudgetScope, tt.req)
			assert.Equal(t, []string{tt.wantReset}, pe.Headers["Retry-After"])

			clock = time.Date(2026, 11, 1, 0, 0, 1, 0, time.UTC)
			if strings.Contains(tt.name, "day") {
				clock = time.Date(2026, 10, 3, 0, 0, 1, 0, time.UTC)
			}
			assert.Equal(t, http.StatusOK, admit(p, tt.settings, consumerBudgetScope, tt.req), "the next period starts from zero")
		})
	}
}

func TestSecondWindows(t *testing.T) {
	p := New(nil, nil, nil)
	for window, wantErr := range map[string]bool{"1s": false, "30s": false, "0s": true, "-1s": true} {
		err := p.ValidateConfig(map[string]any{"aggregate": map[string]any{"max": 10, "time_window": window}})
		assert.Equal(t, wantErr, err != nil, window)
	}
}

// A one-second window holds its counter for one second, then the budget is back.
func TestSecondWindow_CounterExpiresAfterOneSecond(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	p, mr := newClockedPlugin(t, &now)
	settings := map[string]any{"aggregate": map[string]any{"max": 100, "time_window": "1s"}}
	spend(t, p, settings, consumerBudgetScope, llmRequest("", nil), 100)
	assert.Equal(t, time.Second, mr.TTL("trl:tk-1:consumer:c-1"))

	pe := refusal(t, p, settings, consumerBudgetScope, llmRequest("", nil))
	assert.Equal(t, []string{"1"}, pe.Headers["Retry-After"])

	mr.FastForward(time.Second)
	assert.Equal(t, http.StatusOK, admit(p, settings, consumerBudgetScope, llmRequest("", nil)))
}

// cmdHook records the Redis commands of a plugin and can answer TTL itself.
type cmdHook struct {
	mu     sync.Mutex
	names  []string
	ttl    time.Duration
	hasTTL bool
}

func (h *cmdHook) DialHook(next redis.DialHook) redis.DialHook { return next }
func (h *cmdHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		h.mu.Lock()
		h.names = append(h.names, cmd.Name())
		h.mu.Unlock()
		if d, ok := cmd.(*redis.DurationCmd); ok && h.hasTTL && cmd.Name() == "ttl" {
			d.SetVal(h.ttl)
			return nil
		}
		return next(ctx, cmd)
	}
}
func (h *cmdHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return next
}
func (h *cmdHook) count(name string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, c := range h.names {
		if c == name {
			n++
		}
	}
	return n
}

// The reset headers come from the TTL command, as they always did: Redis rounds
// TTL to the nearest second, which PTTL truncated would not reproduce.
func TestBudget429_ResetHeadersComeFromTheTTLCommand(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPlugin(t, &now)
	settings := map[string]any{"aggregate": map[string]any{"max": 100, "time_window": "10m"}}
	spend(t, p, settings, consumerBudgetScope, llmRequest("", nil), 100)
	hook := &cmdHook{ttl: 42 * time.Second, hasTTL: true}
	p.redis.AddHook(hook)

	pe := refusal(t, p, settings, consumerBudgetScope, llmRequest("", nil))

	assert.Equal(t, []string{"42s"}, pe.Headers["X-Ratelimit-Reset-Tokens"])
	assert.Equal(t, []string{"600"}, pe.Headers["Retry-After"], "Retry-After has its own rounding")
}

// Only a refused request pays for the Retry-After lookup.
func TestBudgetGate_AdmittedRequestsDoNotComputeRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPlugin(t, &now)
	settings := map[string]any{"aggregate": map[string]any{"max": 100, "time_window": "10m"}}
	spend(t, p, settings, consumerBudgetScope, llmRequest("", nil), 10)
	hook := &cmdHook{}
	p.redis.AddHook(hook)

	require.Equal(t, http.StatusOK, admit(p, settings, consumerBudgetScope, llmRequest("", nil)))

	assert.Zero(t, hook.count("pttl"))
	assert.Equal(t, 1, hook.count("ttl"))
}

// With several windows breached, Retry-After clears the longest one while the
// reset headers keep describing the reported window.
func TestBudget429_RetryAfterIsTheLongestBreachedWindow(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	p, _ := newClockedPlugin(t, &now)
	settings := map[string]any{
		"per_model": true,
		"rules":     []map[string]any{{"model": "model-a", "max": 100, "time_window": "10m"}},
		"aggregate": map[string]any{"max": 100, "time_window": "1h"},
	}
	req := llmRequest(`{"model":"model-a"}`, nil)
	spend(t, p, settings, consumerBudgetScope, req, 100)

	pe := refusal(t, p, settings, consumerBudgetScope, req)

	assert.Equal(t, []string{"600s"}, pe.Headers["X-Ratelimit-Reset-Tokens"])
	assert.Equal(t, []string{"3600"}, pe.Headers["Retry-After"])
}
