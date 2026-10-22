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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	keygroupdomain "github.com/NeuralTrust/TrustGate/pkg/domain/keygroup"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// groupGateway is a real id, so a notice names the gateway it came from.
var groupGateway = ids.New[ids.GatewayKind]()

type noticeLog struct {
	mu   sync.Mutex
	got  []keygroupdomain.Reached
	fail error
}

func (n *noticeLog) Notify(_ context.Context, event keygroupdomain.Reached) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.got = append(n.got, event)
	return n.fail
}

func (n *noticeLog) events() []keygroupdomain.Reached {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]keygroupdomain.Reached(nil), n.got...)
}

func newClockedGroupBudget(t *testing.T, now *time.Time, notifier keygroupdomain.Notifier) (*GroupBudget, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	g := NewGroupBudget(rdb, adapter.NewRegistry(), nil, notifier, slog.New(slog.DiscardHandler))
	g.base.now = func() time.Time { return *now }
	g.spawn = func(fn func()) { fn() }
	return g, mr
}

func newDownGroupBudget(t *testing.T) *GroupBudget {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1, DialerRetries: 1})
	t.Cleanup(func() { _ = rdb.Close() })
	mr.Close()
	g := NewGroupBudget(rdb, adapter.NewRegistry(), nil, nil, slog.New(slog.DiscardHandler))
	g.spawn = func(fn func()) { fn() }
	return g
}

func groupLimits(t *testing.T, monthly, member *float64, overrides map[string]float64, action string) *keygroupdomain.Budget {
	t.Helper()
	b, err := keygroupdomain.NewBudget(groupGateway, "g-eng", monthly, member, overrides, action, time.Now())
	require.NoError(t, err)
	return b
}

func usdLimit(v float64) *float64 { return &v }

// groupKey is a group key of owner in g-eng, held to b.
func groupKey(owner string, b *keygroupdomain.Budget) appplugins.RuntimeScope {
	return appplugins.RuntimeScope{
		GatewayID: groupGateway.String(), ConsumerID: "p-1", AuthID: "auth-" + owner, OwnerID: owner,
		KeyGroupID: "g-eng", KeyGroupBudget: b,
	}
}

type groupOutcome struct {
	status   int
	errType  string
	scope    string
	decision string
	failure  string
}

func runGroup(ctx context.Context, t *testing.T, g *GroupBudget, scope appplugins.RuntimeScope, stage policy.Stage, req *infracontext.RequestContext, resp *infracontext.ResponseContext) (groupOutcome, *appplugins.PluginError) {
	t.Helper()
	span := trace.New("t", trace.Metadata{}).StartSpan(trace.SpanPlugin, GroupBudgetPluginName)
	in := appplugins.ExecInput{
		Stage:    stage,
		Mode:     policy.ModeEnforce,
		Config:   policy.PluginConfig{ID: "kgb", Slug: GroupBudgetPluginName, Name: GroupBudgetPluginName},
		Scope:    scope,
		Request:  req,
		Response: resp,
		Event:    metrics.NewEventContext(span),
	}
	res, err := g.Execute(ctx, in)
	attrs := span.PluginAttrsCopy()
	out := groupOutcome{decision: attrs.Decision}
	if data, ok := attrs.Extras.(KeyGroupBudgetData); ok {
		out.failure = data.FailureDetail
	}
	if pe, ok := appplugins.AsPluginError(err); ok {
		var body struct {
			Error struct {
				Type  string `json:"type"`
				Scope string `json:"scope"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(pe.Body, &body))
		out.status, out.errType, out.scope = pe.StatusCode, body.Error.Type, body.Error.Scope
		return out, pe
	}
	if err != nil {
		out.status = http.StatusInternalServerError
		return out, nil
	}
	out.status = res.StatusCode
	return out, nil
}

func admitGroup(t *testing.T, g *GroupBudget, scope appplugins.RuntimeScope) (groupOutcome, *appplugins.PluginError) {
	t.Helper()
	return runGroup(context.Background(), t, g, scope, policy.StagePreRequest, registryPriced("gpt-4o-mini"), &infracontext.ResponseContext{})
}

// spendGroup charges tokens at $0.001 each: 1000 tokens are a dollar.
func spendGroup(t *testing.T, g *GroupBudget, scope appplugins.RuntimeScope, tokens int) {
	t.Helper()
	body := fmt.Appendf(nil, `{"id":"x","model":"gpt-4o-mini","choices":[{"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":%d,"completion_tokens":0,"total_tokens":%d}}`, tokens, tokens)
	out, _ := runGroup(context.Background(), t, g, scope, policy.StagePostResponse, registryPriced("gpt-4o-mini"), &infracontext.ResponseContext{StatusCode: http.StatusOK, Body: body})
	require.Less(t, out.status, http.StatusBadRequest, "a charge never refuses the answer")
}

func TestGroupBudget_CountsTheGroupAndTheMemberPerUTCMonth(t *testing.T) {
	now := time.Date(2026, 10, 31, 23, 0, 0, 0, time.UTC)
	g, mr := newClockedGroupBudget(t, &now, nil)
	alice := groupKey("alice", groupLimits(t, usdLimit(100), usdLimit(20), nil, keygroupdomain.ActionBlock))

	spendGroup(t, g, alice, 1500)
	spendGroup(t, g, groupKey("bob", alice.KeyGroupBudget), 500)

	group := "kgb:" + groupGateway.String() + ":g-eng"
	mr.CheckGet(t, group+":p:2026-10", "2000000")
	mr.CheckGet(t, group+":owner:alice:p:2026-10", "1500000")
	mr.CheckGet(t, group+":owner:bob:p:2026-10", "500000")
	ttl := mr.TTL(group + ":p:2026-10")
	assert.Positive(t, ttl, "a month's counter expires once the month is over")
	assert.LessOrEqual(t, ttl, time.Hour, "the counter lives to the end of its month")

	now = time.Date(2026, 11, 1, 0, 0, 1, 0, time.UTC)
	spendGroup(t, g, alice, 100)
	mr.CheckGet(t, group+":p:2026-11", "100000")
	mr.CheckGet(t, group+":p:2026-10", "2000000")
}

func TestGroupBudget_BlockingBudgetRefusesOnceALimitIsReached(t *testing.T) {
	tests := []struct {
		name      string
		budget    func(t *testing.T) *keygroupdomain.Budget
		spend     map[string]int
		admitted  map[string]bool
		wantScope string
	}{
		{
			name: "the group's total binds every member",
			budget: func(t *testing.T) *keygroupdomain.Budget {
				return groupLimits(t, usdLimit(2), nil, nil, keygroupdomain.ActionBlock)
			},
			spend:     map[string]int{"alice": 1500, "bob": 500},
			admitted:  map[string]bool{"alice": false, "bob": false, "carol": false},
			wantScope: keygroupdomain.ScopeGroup,
		},
		{
			name: "a member's share binds that member only",
			budget: func(t *testing.T) *keygroupdomain.Budget {
				return groupLimits(t, nil, usdLimit(1), nil, keygroupdomain.ActionBlock)
			},
			spend:     map[string]int{"alice": 1000, "bob": 999},
			admitted:  map[string]bool{"alice": false, "bob": true, "carol": true},
			wantScope: keygroupdomain.ScopeMember,
		},
		{
			name: "an override replaces the member default",
			budget: func(t *testing.T) *keygroupdomain.Budget {
				return groupLimits(t, nil, usdLimit(1), map[string]float64{"alice": 5, "bob": 0}, keygroupdomain.ActionBlock)
			},
			spend:     map[string]int{"alice": 1000, "carol": 1000},
			admitted:  map[string]bool{"alice": true, "bob": false, "carol": false},
			wantScope: keygroupdomain.ScopeMember,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
			g, _ := newClockedGroupBudget(t, &now, nil)
			b := tt.budget(t)
			for owner, tokens := range tt.spend {
				spendGroup(t, g, groupKey(owner, b), tokens)
			}
			for owner, admitted := range tt.admitted {
				got, _ := admitGroup(t, g, groupKey(owner, b))
				if admitted {
					assert.Equal(t, groupOutcome{status: http.StatusOK}, got, owner)
					continue
				}
				assert.Equal(t, groupOutcome{status: http.StatusTooManyRequests, errType: groupBudgetExceeded, scope: tt.wantScope, decision: "block"}, got, owner)
			}
		})
	}
}

func TestGroupBudget_TheGroupsTotalIsCheckedFirst(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	g, _ := newClockedGroupBudget(t, &now, nil)
	alice := groupKey("alice", groupLimits(t, usdLimit(1), usdLimit(1), nil, keygroupdomain.ActionBlock))
	spendGroup(t, g, alice, 1000)

	got, pe := admitGroup(t, g, alice)
	require.Equal(t, keygroupdomain.ScopeGroup, got.scope, "both limits are reached; the group's is the one answered")
	var body map[string]map[string]any
	require.NoError(t, json.Unmarshal(pe.Body, &body))
	assert.Equal(t, map[string]any{
		"type":      "budget_exceeded",
		"code":      "budget_exceeded",
		"message":   "The monthly budget of this key's group is spent ($1.00 of $1.00). It resets on 2026-11-01 (UTC).",
		"scope":     "group",
		"group_id":  "g-eng",
		"window":    "calendar_month",
		"limit_usd": 1.0,
		"spent_usd": 1.0,
		"resets_at": "2026-11-01T00:00:00Z",
	}, body["error"])
	assert.Equal(t, []string{"dollars"}, pe.Headers[headerBudgetUnit])
	assert.Equal(t, []string{"group"}, pe.Headers[headerBudgetScope])
	assert.Equal(t, []string{"0.000000"}, pe.Headers[headerBudgetRemainingUSD])
}

func TestGroupBudget_MemberMessageNamesTheMembersShare(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	g, _ := newClockedGroupBudget(t, &now, nil)
	alice := groupKey("alice", groupLimits(t, usdLimit(100), usdLimit(0.5), nil, keygroupdomain.ActionBlock))
	spendGroup(t, g, alice, 600)

	_, pe := admitGroup(t, g, alice)
	require.NotNil(t, pe)
	assert.Equal(t, "Your monthly budget in this key's group is spent ($0.60 of $0.50). It resets on 2026-11-01 (UTC).", pe.Message)
}

func TestGroupBudget_AlertingBudgetLetsTheRequestThroughAndRecordsIt(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	g, mr := newClockedGroupBudget(t, &now, nil)
	alice := groupKey("alice", groupLimits(t, usdLimit(1), nil, nil, keygroupdomain.ActionAlert))
	spendGroup(t, g, alice, 1000)

	got, _ := admitGroup(t, g, alice)
	assert.Equal(t, groupOutcome{status: http.StatusOK, decision: "observe"}, got)
	spendGroup(t, g, alice, 500)
	mr.CheckGet(t, "kgb:"+groupGateway.String()+":g-eng:p:2026-10", "1500000")
}

func TestGroupBudget_TellsTheConsoleOncePerLimitAndMonth(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	notices := &noticeLog{}
	g, _ := newClockedGroupBudget(t, &now, notices)
	b := groupLimits(t, usdLimit(2), usdLimit(1), nil, keygroupdomain.ActionAlert)
	alice, bob := groupKey("alice", b), groupKey("bob", b)

	spendGroup(t, g, alice, 900)
	require.Empty(t, notices.events())
	spendGroup(t, g, alice, 200) // alice crosses her $1
	spendGroup(t, g, alice, 100)
	_, _ = admitGroup(t, g, alice)
	spendGroup(t, g, bob, 900) // the group crosses its $2
	spendGroup(t, g, bob, 100) // bob reaches his $1

	got := notices.events()
	require.Len(t, got, 3)
	assert.Equal(t, keygroupdomain.Reached{
		GatewayID: groupGateway, GroupID: "g-eng", Scope: keygroupdomain.ScopeMember, UserID: "alice",
		LimitUSD: 1, SpentUSD: 1.1, Period: "2026-10", Action: keygroupdomain.ActionAlert,
	}, got[0])
	assert.Equal(t, keygroupdomain.Reached{
		GatewayID: groupGateway, GroupID: "g-eng", Scope: keygroupdomain.ScopeGroup,
		LimitUSD: 2, SpentUSD: 2.1, Period: "2026-10", Action: keygroupdomain.ActionAlert,
	}, got[1])
	assert.Equal(t, keygroupdomain.ScopeMember, got[2].Scope)
	assert.Equal(t, "bob", got[2].UserID)

	now = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	spendGroup(t, g, alice, 1000)
	require.Len(t, notices.events(), 4, "a new month announces again")
	assert.Equal(t, "2026-11", notices.events()[3].Period)
}

// A limit lowered below what the month already spent is reached without a
// charge crossing it: the request that finds it so tells the console, once.
func TestGroupBudget_ALoweredLimitIsAnnouncedAtTheGate(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	notices := &noticeLog{fail: errors.New("console down")}
	g, _ := newClockedGroupBudget(t, &now, notices)
	spendGroup(t, g, groupKey("alice", groupLimits(t, usdLimit(100), nil, nil, keygroupdomain.ActionBlock)), 3000)
	lowered := groupKey("alice", groupLimits(t, usdLimit(2), nil, nil, keygroupdomain.ActionBlock))

	got, _ := admitGroup(t, g, lowered)
	require.Equal(t, http.StatusTooManyRequests, got.status)
	_, _ = admitGroup(t, g, lowered)
	require.Len(t, notices.events(), 1, "a console that failed is not retried by every request")
	assert.Equal(t, 3.0, notices.events()[0].SpentUSD)
}

func TestGroupBudget_CounterStoreDown(t *testing.T) {
	block := groupLimits(t, usdLimit(1), nil, nil, keygroupdomain.ActionBlock)
	alert := groupLimits(t, usdLimit(1), nil, nil, keygroupdomain.ActionAlert)
	usage := &infracontext.ResponseContext{StatusCode: http.StatusOK, Body: usageResponseBody()}
	tests := []struct {
		name   string
		budget *keygroupdomain.Budget
		stage  policy.Stage
		resp   *infracontext.ResponseContext
		want   groupOutcome
	}{
		{name: "a blocking budget fails closed", budget: block, stage: policy.StagePreRequest, resp: &infracontext.ResponseContext{},
			want: groupOutcome{status: http.StatusServiceUnavailable, errType: budgetUnavailable, scope: groupBudgetScope, decision: decisionFailedClosed, failure: "read_counter"}},
		{name: "an alerting budget fails open", budget: alert, stage: policy.StagePreRequest, resp: &infracontext.ResponseContext{},
			want: groupOutcome{status: http.StatusOK, decision: "failed_open", failure: "read_counter"}},
		{name: "a charge that cannot be recorded lets the answer through", budget: block, stage: policy.StagePostResponse, resp: usage,
			want: groupOutcome{status: http.StatusOK, decision: "failed_open", failure: "record_cost"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, pe := runGroup(context.Background(), t, newDownGroupBudget(t), groupKey("alice", tt.budget), tt.stage, registryPriced("gpt-4o-mini"), tt.resp)
			assert.Equal(t, tt.want, got)
			if pe != nil {
				assert.Equal(t, []string{budgetUnavailableRetryAfter}, pe.Headers[headerRetryAfter])
			}
		})
	}
}

func TestGroupBudget_UnpricedModel(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	g, mr := newClockedGroupBudget(t, &now, nil)
	unpriced := llmRequest(`{"model":"gpt-4o-mini"}`, nil)

	got, pe := runGroup(context.Background(), t, g, groupKey("alice", groupLimits(t, usdLimit(1), nil, nil, keygroupdomain.ActionBlock)),
		policy.StagePreRequest, unpriced, &infracontext.ResponseContext{})
	assert.Equal(t, groupOutcome{status: http.StatusForbidden, errType: modelUnpriced, scope: groupBudgetScope, decision: "block"}, got)
	assert.True(t, pe.NotAVerdict, "a model with no price is not a policy verdict")

	alert := groupKey("alice", groupLimits(t, usdLimit(1), nil, nil, keygroupdomain.ActionAlert))
	got, _ = runGroup(context.Background(), t, g, alert, policy.StagePreRequest, unpriced, &infracontext.ResponseContext{})
	assert.Equal(t, groupOutcome{status: http.StatusOK, decision: "observe"}, got)
	got, _ = runGroup(context.Background(), t, g, alert, policy.StagePostResponse, unpriced, &infracontext.ResponseContext{StatusCode: http.StatusOK, Body: usageResponseBody()})
	assert.Less(t, got.status, http.StatusBadRequest)
	assert.Empty(t, mr.Keys(), "an unpriced answer accrues nothing")
}

func TestGroupBudget_HoldsOnlyAGroupKeyWithABudget(t *testing.T) {
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	g, mr := newClockedGroupBudget(t, &now, nil)
	b := groupLimits(t, usdLimit(1), nil, nil, keygroupdomain.ActionBlock)
	noBudget := groupKey("alice", nil)
	personal := groupKey("alice", b)
	personal.KeyGroupID = ""
	noOwner := groupKey("", b)
	noMemberLimit := groupKey("alice", groupLimits(t, nil, nil, map[string]float64{"bob": 1}, keygroupdomain.ActionBlock))

	for name, scope := range map[string]appplugins.RuntimeScope{"no budget": noBudget, "a personal key": personal, "no owner": noOwner, "no limit for this member": noMemberLimit} {
		got, _ := runGroup(context.Background(), t, g, scope, policy.StagePreRequest, llmRequest(`{"model":"gpt-4o-mini"}`, nil), &infracontext.ResponseContext{})
		assert.Equal(t, groupOutcome{status: http.StatusOK}, got, name)
		spendGroup(t, g, scope, 1000)
	}
	assert.Empty(t, mr.Keys())
}
