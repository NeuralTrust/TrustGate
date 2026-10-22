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
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	keygroupdomain "github.com/NeuralTrust/TrustGate/pkg/domain/keygroup"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/llmcost"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/redis/go-redis/v9"
)

// GroupBudgetPluginName names the stage that holds a group key to its group's
// budget. It is not in the plugin registry: no policy can name it, and the
// proxy adds it to a store request made with a group key whose group has a
// budget.
const GroupBudgetPluginName = "key_group_budget"

const (
	groupCounterPrefix  = "kgb"
	groupNoticePrefix   = "kgb:notified"
	groupBudgetExceeded = "budget_exceeded"
	groupBudgetScope    = "key_group"

	// groupNoticeTimeout bounds the call that tells the console a limit was
	// reached; the request does not wait for it.
	groupNoticeTimeout = 10 * time.Second
	// groupNoticeGrace keeps the once-per-month marker a day past the month,
	// so a request the month admitted that ends after it is not announced
	// again.
	groupNoticeGrace = 24 * time.Hour
)

var _ appplugins.Plugin = (*GroupBudget)(nil)

// GroupBudget holds a group key to its group's monthly budget: the group's
// total and the member's own share, in micro-dollars of priced cost, on Redis
// counters per UTC calendar month. It shares the counting of the
// token_rate_limiter's key-partitioned dollar budgets: the model it charges is
// the one served, a request is charged to the month that admitted it, and the
// rules for a counter store that cannot be reached and for a model with no
// price are the same, with the budget's action in place of the policy's mode:
// a blocking budget fails closed (503 budget_unavailable) and refuses an
// unpriced model (403 model_unpriced); an alerting one lets the request
// through and records it.
type GroupBudget struct {
	base     *Plugin
	notifier keygroupdomain.Notifier
	logger   *slog.Logger
	// spawn runs the console notice off the request. Tests run it inline.
	spawn func(func())
}

// NewGroupBudget returns the stage over the token_rate_limiter's counter
// store, response decoders and pricing. notifier may be nil: limits are still
// enforced, and nobody is told.
func NewGroupBudget(redisClient *redis.Client, registry *adapter.Registry, pricing appcatalog.PricingResolver, notifier keygroupdomain.Notifier, logger *slog.Logger) *GroupBudget {
	if logger == nil {
		logger = slog.Default()
	}
	return &GroupBudget{
		base:     New(redisClient, registry, pricing),
		notifier: notifier,
		logger:   logger,
		spawn:    func(fn func()) { go fn() },
	}
}

func (g *GroupBudget) Name() string { return GroupBudgetPluginName }

func (g *GroupBudget) MutatesRequestBody() bool { return false }

func (g *GroupBudget) MutatesResponseBody() bool { return false }

func (g *GroupBudget) MutatesMetadata() bool { return false }

func (g *GroupBudget) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}
}

func (g *GroupBudget) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest, policy.StagePostResponse}
}

func (g *GroupBudget) SupportedProtocols() []appplugins.Protocol {
	return []appplugins.Protocol{appplugins.ProtocolLLM}
}

func (g *GroupBudget) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce, policy.ModeObserve}
}

// ValidateConfig accepts anything: the stage reads its budget from the
// request, never from settings.
func (g *GroupBudget) ValidateConfig(map[string]any) error { return nil }

// KeyGroupBudgetData is what the stage records on its span.
type KeyGroupBudgetData struct {
	Stage    string `json:"stage"`
	GroupID  string `json:"group_id"`
	Action   string `json:"action"`
	Period   string `json:"period"`
	Provider string `json:"provider,omitempty"`
	Model    string `json:"model,omitempty"`
	// Scope is the limit reported: the one reached, else the group's total
	// when there is one, else the member's.
	Scope            string `json:"scope,omitempty"`
	LimitMicroUSD    int64  `json:"limit_micro_usd,omitempty"`
	ConsumedMicroUSD int64  `json:"consumed_micro_usd,omitempty"`
	CostMicroUSD     int64  `json:"cost_micro_usd,omitempty"`
	LimitExceeded    bool   `json:"limit_exceeded"`
	Unpriced         bool   `json:"unpriced,omitempty"`
	// FailureReason, FailureDetail and FailureErrorClass are set only when the
	// counter store could not be read or written, as on token_rate_limiter.
	FailureReason     string `json:"failure_reason,omitempty"`
	FailureDetail     string `json:"failure_detail,omitempty"`
	FailureErrorClass string `json:"failure_error_class,omitempty"`
}

// groupWindow is one limit a request is held to this month.
type groupWindow struct {
	scope    string
	key      string
	limitUSD float64
	max      int64
}

// groupRun is one execution: the budget, who it holds and the month.
type groupRun struct {
	budget    *keygroupdomain.Budget
	gatewayID string
	groupID   string
	ownerID   string
	period    string
	ttl       int
	windows   []groupWindow
}

func (g *GroupBudget) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	run, ok := g.runFor(in)
	if !ok {
		return &appplugins.Result{StatusCode: http.StatusOK}, nil
	}
	switch in.Stage {
	case policy.StagePreRequest:
		return g.gate(ctx, run, in.Request, in.Event)
	case policy.StagePostResponse:
		return g.charge(ctx, run, in.Request, in.Response, in.Event)
	default:
		return &appplugins.Result{StatusCode: http.StatusOK}, nil
	}
}

// runFor is what in holds the request to: nothing unless a group key with an
// owner made it and its group has a budget with a limit for it.
func (g *GroupBudget) runFor(in appplugins.ExecInput) (groupRun, bool) {
	b := in.Scope.KeyGroupBudget
	if in.Request == nil || in.Request.Provider == "" || b == nil || in.Scope.KeyGroupID == "" || in.Scope.OwnerID == "" {
		return groupRun{}, false
	}
	clock := g.base.clockFor(in.Request)
	period, ttl, _ := calendarPeriod(windowCalendarMonth, clock.at, clock.now)
	run := groupRun{
		budget:    b,
		gatewayID: in.Scope.GatewayID,
		groupID:   in.Scope.KeyGroupID,
		ownerID:   in.Scope.OwnerID,
		period:    period,
		ttl:       ttl,
	}
	group := groupCounterPrefix + ":" + run.gatewayID + ":" + url.QueryEscape(run.groupID)
	if limit, ok := b.GroupLimit(); ok {
		run.windows = append(run.windows, groupWindow{scope: keygroupdomain.ScopeGroup, key: periodKey(group, period), limitUSD: limit, max: microLimit(limit)})
	}
	if limit, ok := b.MemberLimit(run.ownerID); ok {
		member := group + ":owner:" + url.QueryEscape(run.ownerID)
		run.windows = append(run.windows, groupWindow{scope: keygroupdomain.ScopeMember, key: periodKey(member, period), limitUSD: limit, max: microLimit(limit)})
	}
	return run, len(run.windows) > 0
}

// microLimit is a dollar limit in micro-dollars. A limit too small to count
// still allows something, as on token_rate_limiter; zero allows nothing.
func microLimit(usd float64) int64 {
	micros := llmcost.MicroUSD(usd)
	if micros == 0 && usd > 0 {
		return 1
	}
	return micros
}

// mode is the policy mode the budget's action stands for: a blocking budget
// enforces, an alerting one observes.
func (r groupRun) mode() policy.Mode {
	if r.budget.Blocks() {
		return policy.ModeEnforce
	}
	return policy.ModeObserve
}

func (r groupRun) data(stage policy.Stage, req *infracontext.RequestContext, model string) KeyGroupBudgetData {
	data := KeyGroupBudgetData{
		Stage:   string(stage),
		GroupID: r.groupID,
		Action:  r.budget.Action,
		Period:  r.period,
		Model:   model,
	}
	if req != nil {
		data.Provider = req.Provider
	}
	return data
}

// gate refuses, under a blocking budget, a request whose group or member has
// reached its limit this month. The group's total is checked first.
func (g *GroupBudget) gate(ctx context.Context, run groupRun, req *infracontext.RequestContext, event *metrics.EventContext) (*appplugins.Result, error) {
	model := chargedModel(req, true)
	data := run.data(policy.StagePreRequest, req, model)
	mode := run.mode()

	if !g.priced(ctx, req, model) {
		data.Unpriced = true
		appplugins.SetDecision(event, mode)
		if appplugins.Blocks(mode) {
			setGroupExtras(event, data)
			return nil, groupUnpricedError(model)
		}
	}

	consumed := make([]int64, len(run.windows))
	reached := -1
	for i, w := range run.windows {
		spent, err := g.base.redis.Get(ctx, w.key).Int64()
		if err != nil && !errors.Is(err, redis.Nil) {
			return g.counterFailed(ctx, policy.StagePreRequest, mode, event, data, "read_counter", err)
		}
		consumed[i] = spent
		if reached == -1 && exceeds(spent, float64(w.max)) {
			reached = i
		}
	}

	report := reached
	if report == -1 {
		report = 0
	}
	w := run.windows[report]
	data.Scope, data.LimitMicroUSD, data.ConsumedMicroUSD = w.scope, w.max, consumed[report]
	if reached == -1 {
		setGroupExtras(event, data)
		return &appplugins.Result{StatusCode: http.StatusOK}, nil
	}

	data.LimitExceeded = true
	setGroupExtras(event, data)
	appplugins.SetDecision(event, mode)
	// A limit can be met here before any charge crosses it: one lowered below
	// what was already spent. The notice is once a month all the same.
	for i, w := range run.windows {
		if exceeds(consumed[i], float64(w.max)) {
			g.reached(ctx, run, w, consumed[i])
		}
	}
	if !appplugins.Blocks(mode) {
		return &appplugins.Result{StatusCode: http.StatusOK}, nil
	}
	reset := g.base.resetSeconds(ctx, w.key, run.ttl)
	return nil, groupExceededError(run, w, consumed[report], reset)
}

// charge adds the priced cost of the answer to the group's and the member's
// counters, and tells the console about a limit the charge reaches.
func (g *GroupBudget) charge(ctx context.Context, run groupRun, req *infracontext.RequestContext, resp *infracontext.ResponseContext, event *metrics.EventContext) (*appplugins.Result, error) {
	if resp == nil {
		return &appplugins.Result{}, nil
	}
	model := chargedModel(req, true)
	data := run.data(policy.StagePostResponse, req, model)
	usage, servedModel := g.base.extractUsageAndModel(req, resp)
	rates, found := g.rates(ctx, req, model, servedModel)
	if !found {
		g.logger.WarnContext(ctx, "key_group_budget: unpriced model, accruing zero",
			slog.String("provider", data.Provider),
			slog.String("model", model),
			slog.String("served_model", servedModel))
		data.Unpriced = true
		setGroupExtras(event, data)
		return &appplugins.Result{}, nil
	}
	if usage == nil {
		return &appplugins.Result{}, nil
	}
	prompt, completion := rates.CostUSD(usage)
	micros := llmcost.MicroUSD(prompt + completion)
	if micros <= 0 {
		return &appplugins.Result{}, nil
	}
	data.CostMicroUSD = micros

	for i, w := range run.windows {
		total, err := recordScript.Run(ctx, g.base.redis, []string{w.key}, micros, run.ttl).Int64()
		if err != nil {
			return g.counterFailed(ctx, policy.StagePostResponse, run.mode(), event, data, "record_cost", err)
		}
		if i == 0 {
			data.Scope, data.LimitMicroUSD, data.ConsumedMicroUSD = w.scope, w.max, total
		}
		if exceeds(total, float64(w.max)) && !exceeds(total-micros, float64(w.max)) {
			g.reached(ctx, run, w, total)
		}
	}
	setGroupExtras(event, data)
	return &appplugins.Result{StatusCode: http.StatusOK}, nil
}

func (g *GroupBudget) priced(ctx context.Context, req *infracontext.RequestContext, model string) bool {
	_, found := g.rates(ctx, req, model)
	return found
}

func (g *GroupBudget) rates(ctx context.Context, req *infracontext.RequestContext, models ...string) (llmcost.Rates, bool) {
	provider, requested := "", ""
	var overlay *llmcost.RegistryRates
	if req != nil {
		provider, requested = req.Provider, req.RequestedModel
		overlay = llmcost.RatesFromDomain(req.RegistryPricing)
	}
	return llmcost.Resolve(ctx, g.base.pricing, nil, overlay, provider, append(models, requested, resolvedModel(req))...)
}

// counterFailed follows token_rate_limiter's key-partitioned rule: a blocking
// budget whose counters cannot be read refuses the request (503
// budget_unavailable, Retry-After); every other failure lets it through and
// records it.
func (g *GroupBudget) counterFailed(
	ctx context.Context,
	stage policy.Stage,
	mode policy.Mode,
	event *metrics.EventContext,
	data KeyGroupBudgetData,
	detail string,
	err error,
) (*appplugins.Result, error) {
	failure := appplugins.CounterFailure{Ctx: ctx, Plugin: GroupBudgetPluginName, Stage: stage, Mode: mode, Detail: detail, Err: err, Logger: g.logger, Event: event}
	data.FailureReason = string(appplugins.FailureCounterUnavailable)
	data.FailureDetail = detail
	data.FailureErrorClass = appplugins.CounterErrorClass(err)
	if stage == policy.StagePreRequest && appplugins.Blocks(mode) && ctx.Err() == nil {
		appplugins.LogCounterFailure(failure, decisionFailedClosed)
		setGroupExtras(event, data)
		appplugins.SetDecisionFromOutcome(event, decisionFailedClosed)
		return nil, groupUnavailableError()
	}
	result, ferr := appplugins.HandleCounterFailure(failure)
	if ferr != nil {
		return nil, ferr
	}
	setGroupExtras(event, data)
	return result, nil
}

// reached tells the console that w met its limit, once per limit and month:
// the first replica to set the month's marker sends the notice.
func (g *GroupBudget) reached(ctx context.Context, run groupRun, w groupWindow, spent int64) {
	if g.notifier == nil {
		return
	}
	member := ""
	if w.scope == keygroupdomain.ScopeMember {
		member = run.ownerID
	}
	marker := groupNoticePrefix + ":" + run.gatewayID + ":" + url.QueryEscape(run.groupID) + ":" + w.scope + ":" + url.QueryEscape(member) + ":" + run.period
	ttl := time.Duration(run.ttl)*time.Second + groupNoticeGrace
	first, err := g.base.redis.SetNX(ctx, marker, 1, ttl).Result()
	if err != nil || !first {
		if err != nil {
			g.logger.WarnContext(ctx, "key_group_budget: limit notice not sent, its marker could not be set",
				slog.String("group_id", run.groupID), slog.String("scope", w.scope), slog.String("error_class", appplugins.CounterErrorClass(err)))
		}
		return
	}
	gatewayID, _ := ids.Parse[ids.GatewayKind](run.gatewayID)
	event := keygroupdomain.Reached{
		GatewayID: gatewayID,
		GroupID:   run.groupID,
		Scope:     w.scope,
		UserID:    member,
		LimitUSD:  w.limitUSD,
		SpentUSD:  float64(spent) / 1e6,
		Period:    run.period,
		Action:    run.budget.Action,
	}
	g.spawn(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), groupNoticeTimeout)
		defer cancel()
		if err := g.notifier.Notify(ctx, event); err != nil {
			g.logger.WarnContext(ctx, "key_group_budget: tell the console a limit was reached",
				slog.String("gateway_id", run.gatewayID),
				slog.String("group_id", run.groupID),
				slog.String("scope", w.scope),
				slog.String("error", err.Error()))
		}
	})
}

// groupExceededError is the 429 a blocking budget answers once a limit is
// reached, naming which one.
func groupExceededError(run groupRun, w groupWindow, consumed int64, resetSeconds int) *appplugins.PluginError {
	resetsAt := monthEnd(run.period)
	spent, limit := float64(consumed)/1e6, w.limitUSD
	message := fmt.Sprintf("The monthly budget of this key's group is spent ($%.2f of $%.2f). It resets on %s (UTC).", spent, limit, resetsAt.Format("2006-01-02"))
	if w.scope == keygroupdomain.ScopeMember {
		message = fmt.Sprintf("Your monthly budget in this key's group is spent ($%.2f of $%.2f). It resets on %s (UTC).", spent, limit, resetsAt.Format("2006-01-02"))
	}
	headers := dollarBudgetHeaders(w.max, consumed, w.scope, windowCalendarMonth, resetSeconds)
	pe := budgetError(http.StatusTooManyRequests, groupBudgetExceeded, headers, map[string]any{
		"code":      groupBudgetExceeded,
		"message":   message,
		"scope":     w.scope,
		"group_id":  run.groupID,
		"window":    windowCalendarMonth,
		"limit_usd": limit,
		"spent_usd": spent,
		"resets_at": resetsAt.Format(time.RFC3339),
	})
	pe.Type = groupBudgetExceeded
	pe.Message = message
	return pe
}

func groupUnavailableError() *appplugins.PluginError {
	headers := map[string][]string{headerRetryAfter: {budgetUnavailableRetryAfter}}
	return budgetError(http.StatusServiceUnavailable, budgetUnavailable, headers, map[string]any{"scope": groupBudgetScope})
}

func groupUnpricedError(model string) *appplugins.PluginError {
	pe := budgetError(http.StatusForbidden, modelUnpriced, nil, map[string]any{"scope": groupBudgetScope, "model": model})
	pe.NotAVerdict = true
	return pe
}

// monthEnd is the start of the month after period ("2006-01"), when its
// counters reset.
func monthEnd(period string) time.Time {
	start, err := time.Parse("2006-01", period)
	if err != nil {
		return time.Time{}
	}
	return start.AddDate(0, 1, 0)
}

func setGroupExtras(event *metrics.EventContext, data KeyGroupBudgetData) {
	if event == nil {
		return
	}
	event.SetExtras(data)
}
