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

package consumer

import (
	"log/slog"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// PolicyRef identifies a scoped policy in scope decisions without carrying
// the whole policy.
type PolicyRef struct {
	ID   string
	Name string
	Slug string
}

// SkippedPolicy is a scoped policy that did not run on a tools/call, with the
// scope dimension that rejected it.
type SkippedPolicy struct {
	PolicyRef
	Reason policydomain.SkipReason
}

// ScopeDecision explains which scoped policies of a consumer entered the plan
// of one tools/call and which did not. Evaluated counts the enabled policies
// with a scope the consumer carries; unscoped policies run everywhere and are
// never listed here. Matched and Skipped partition those Evaluated policies.
type ScopeDecision struct {
	Evaluated int
	Matched   []PolicyRef
	Skipped   []SkippedPolicy
}

type scopedEntry struct {
	ref   PolicyRef
	scope *policydomain.MCPScope
	plan  *appplugins.StagePlan
}

type destPlans struct {
	static    *appplugins.StagePlan
	principal []scopedEntry
	// lower holds the registry-level entries a call to this tool still has to
	// consider, and only exists on a tool destination. A tool-level policy of
	// the same slug beats them; see "the nearer destination wins" below.
	lower []scopedEntry
	// staticSlugs are the slugs this destination applies unconditionally, so a
	// registry-level entry carrying one can be dropped without matching it.
	staticSlugs map[string]struct{}
}

// slugsOf collects the slugs of a policy list, for the override check.
func slugsOf(policies []*policydomain.Policy) map[string]struct{} {
	if len(policies) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(policies))
	for _, pol := range policies {
		out[pol.Slug] = struct{}{}
	}
	return out
}

func entrySlugs(entries []scopedEntry) map[string]struct{} {
	if len(entries) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(entries))
	for i := range entries {
		out[entries[i].ref.Slug] = struct{}{}
	}
	return out
}

func inSlugs(set map[string]struct{}, slug string) bool {
	if set == nil {
		return false
	}
	_, ok := set[slug]
	return ok
}

// PolicyPlans holds the precompiled stage plans an MCP consumer runs on
// tools/call, indexed by destination. Policies scoped only by destination are
// folded into one static plan per registry and per (registry, tool) at config
// load; policies with a principal dimension are kept aside per destination and
// filtered against the caller only when such policies exist for that
// destination.
type PolicyPlans struct {
	base       *appplugins.StagePlan
	anyDest    []scopedEntry
	byRegistry map[ids.RegistryID]*destPlans
	byTool     map[policydomain.MCPTarget]*destPlans
	scoped     []scopedEntry
	// hasPrincipal is true when at least one scoped policy narrows by group.
	// Without one, no matcher ever reads the caller, so the principal never
	// has to be projected — and projecting it means rebuilding the
	// deduplicated group list out of the token claims on every call.
	hasPrincipal bool
}

var planStages = [...]policydomain.Stage{
	policydomain.StagePreRequest,
	policydomain.StagePostRequest,
	policydomain.StagePreResponse,
	policydomain.StagePostResponse,
}

// BuildPolicyPlans precompiles the plans of a consumer from its unscoped
// policies, which form the base every destination inherits, and its scoped
// ones. Disabled policies, empty scopes and policies whose plugin is unknown
// never enter any plan; an enabled empty scope is still kept for Explain, so a
// policy pruned to {} shows up as skipped rather than vanishing. It returns nil
// without a plugin registry, so callers keep falling back to the ad-hoc chain.
func BuildPolicyPlans(
	reg appplugins.Registry,
	unscoped, scoped []*policydomain.Policy,
	logger *slog.Logger,
) *PolicyPlans {
	if reg == nil {
		return nil
	}
	plans := &PolicyPlans{
		base:       appplugins.NewStagePlan(reg, unscoped, logger),
		byRegistry: make(map[ids.RegistryID]*destPlans),
		byTool:     make(map[policydomain.MCPTarget]*destPlans),
	}
	staticByRegistry := make(map[ids.RegistryID][]*policydomain.Policy)
	staticByTool := make(map[policydomain.MCPTarget][]*policydomain.Policy)

	for _, pol := range scoped {
		if pol == nil || !pol.Enabled || pol.MCPScope == nil {
			continue
		}
		scope := pol.MCPScope
		entry := scopedEntry{
			ref:   PolicyRef{ID: pol.ID.String(), Name: pol.Name, Slug: pol.Slug},
			scope: scope,
			plan:  appplugins.NewStagePlan(reg, []*policydomain.Policy{pol}, logger),
		}
		if !hasAnyStage(entry.plan) {
			continue
		}
		plans.scoped = append(plans.scoped, entry)
		plans.hasPrincipal = plans.hasPrincipal || scope.HasPrincipal()
		switch {
		case scope.IsEmpty():
		case !scope.HasPrincipal():
			for _, id := range scope.RegistryIDs {
				staticByRegistry[id] = append(staticByRegistry[id], pol)
			}
			for _, ref := range scope.Tools {
				target := policydomain.MCPTarget(ref)
				staticByTool[target] = append(staticByTool[target], pol)
			}
		case !scope.HasDestination():
			plans.anyDest = append(plans.anyDest, entry)
		default:
			for _, id := range scope.RegistryIDs {
				dest := plans.destForRegistry(id)
				dest.principal = append(dest.principal, entry)
			}
			for _, ref := range scope.Tools {
				dest := plans.destForTool(policydomain.MCPTarget(ref))
				dest.principal = append(dest.principal, entry)
			}
		}
	}

	for id, statics := range staticByRegistry {
		plans.destForRegistry(id).static = appplugins.NewStagePlan(reg, concatPolicies(unscoped, statics), logger)
	}
	// Make sure every tool named by a static policy has a destination before the
	// resolution pass below walks them.
	for target := range staticByTool {
		plans.destForTool(target)
	}
	for target, dest := range plans.byTool {
		plans.resolveToolDest(reg, target, dest, unscoped, staticByRegistry, staticByTool, logger)
	}
	return plans
}

// resolveToolDest settles, for one tool, which of the registry's policies still
// apply to it. The rule is that the nearer destination wins **per slug**: a
// policy attached to (registry, tool) replaces the registry-wide policy of the
// same slug, and every other registry policy keeps running. Whether it wins can
// depend on the caller, which is what the three branches are about.
func (p *PolicyPlans) resolveToolDest(
	reg appplugins.Registry,
	target policydomain.MCPTarget,
	dest *destPlans,
	unscoped []*policydomain.Policy,
	staticByRegistry map[ids.RegistryID][]*policydomain.Policy,
	staticByTool map[policydomain.MCPTarget][]*policydomain.Policy,
	logger *slog.Logger,
) {
	toolStatics := staticByTool[target]
	dest.staticSlugs = slugsOf(toolStatics)
	toolPrincipalSlugs := entrySlugs(dest.principal)

	var keep []*policydomain.Policy
	for _, pol := range staticByRegistry[target.RegistryID] {
		switch {
		case inSlugs(dest.staticSlugs, pol.Slug):
			// A tool-level policy of this slug applies to every caller, so the
			// registry-wide one never runs here. Dropping it is the whole point.
		case inSlugs(toolPrincipalSlugs, pol.Slug):
			// The tool-level policy only covers some callers, so whether this one
			// is replaced cannot be decided now. It stops being precompiled and
			// becomes an entry the request-time pass can drop for the callers the
			// tool policy claims, and keep for the rest.
			dest.lower = append(dest.lower, scopedEntry{
				ref:   PolicyRef{ID: pol.ID.String(), Name: pol.Name, Slug: pol.Slug},
				scope: pol.MCPScope,
				plan:  appplugins.NewStagePlan(reg, []*policydomain.Policy{pol}, logger),
			})
		default:
			keep = append(keep, pol)
		}
	}
	// The registry's own principal-scoped policies lose to the tool the same way.
	if rd, ok := p.byRegistry[target.RegistryID]; ok {
		dest.lower = append(dest.lower, rd.principal...)
	}
	// Nothing was replaced or demoted and the tool adds nothing of its own, so
	// its plan is the registry's plan. Share the pointer instead of compiling an
	// identical one per tool.
	if len(toolStatics) == 0 && len(keep) == len(staticByRegistry[target.RegistryID]) {
		dest.static = p.staticForRegistry(target.RegistryID)
		return
	}
	dest.static = appplugins.NewStagePlan(reg, concatPolicies(unscoped, keep, toolStatics), logger)
}

func (p *PolicyPlans) destForRegistry(id ids.RegistryID) *destPlans {
	dest, ok := p.byRegistry[id]
	if !ok {
		dest = &destPlans{static: p.base}
		p.byRegistry[id] = dest
	}
	return dest
}

func (p *PolicyPlans) destForTool(target policydomain.MCPTarget) *destPlans {
	dest, ok := p.byTool[target]
	if !ok {
		dest = &destPlans{}
		p.byTool[target] = dest
	}
	return dest
}

func (p *PolicyPlans) staticForRegistry(id ids.RegistryID) *appplugins.StagePlan {
	if dest, ok := p.byRegistry[id]; ok {
		return dest.static
	}
	return p.base
}

// PlanFor returns the plan a tools/call against reg and nativeTool runs. It
// resolves the most specific precompiled plan, tool over registry over base,
// with two map lookups and no allocation. Only when principal-scoped policies
// exist for that destination does it read the principal, filter them with the
// scope matcher and union the matches into the static plan. A nil receiver
// returns nil so the executor keeps its ad-hoc chain; a nil principal is an
// identity-less caller that never matches users or groups nor any exception.
func (p *PolicyPlans) PlanFor(
	reg *registrydomain.Registry,
	nativeTool string,
	principal *identity.Principal,
) *appplugins.StagePlan {
	if p == nil {
		return nil
	}
	target := targetOf(reg, nativeTool)
	static, lists, toolStaticSlugs := p.destFor(target)
	if emptyLists(lists) {
		return static
	}
	return p.planWith(target, lists, static, p.callerFor(principal), toolStaticSlugs)
}

// Explain returns the very plan PlanFor returns for the same arguments, plus
// the ScopeDecision that says which scoped policies of the consumer matched
// the destination and caller and which were skipped, with the reason. Unlike
// PlanFor it walks every scoped policy of the consumer and allocates for the
// decision, so the dispatcher only calls it when there is a span to stamp. The
// caller is projected once and shared by both halves. A nil receiver returns
// nil and an empty decision.
func (p *PolicyPlans) Explain(
	reg *registrydomain.Registry,
	nativeTool string,
	principal *identity.Principal,
) (*appplugins.StagePlan, ScopeDecision) {
	if p == nil {
		return nil, ScopeDecision{}
	}
	target := targetOf(reg, nativeTool)
	caller := p.callerFor(principal)
	static, lists, toolStaticSlugs := p.destFor(target)
	return p.planWith(target, lists, static, caller, toolStaticSlugs), p.explain(target, caller)
}

func (p *PolicyPlans) explain(target policydomain.MCPTarget, caller policydomain.MCPCaller) ScopeDecision {
	decision := ScopeDecision{Evaluated: len(p.scoped)}
	if len(p.scoped) == 0 {
		return decision
	}
	// Most destinations reject most scoped policies, so the skipped list is
	// sized for all of them once instead of growing entry by entry.
	decision.Skipped = make([]SkippedPolicy, 0, len(p.scoped))
	for i := range p.scoped {
		entry := &p.scoped[i]
		ok, reason := entry.scope.Matches(target, caller)
		if ok {
			decision.Matched = append(decision.Matched, entry.ref)
			continue
		}
		decision.Skipped = append(decision.Skipped, SkippedPolicy{PolicyRef: entry.ref, Reason: reason})
	}
	return decision
}

func targetOf(reg *registrydomain.Registry, nativeTool string) policydomain.MCPTarget {
	target := policydomain.MCPTarget{Tool: nativeTool}
	if reg != nil {
		target.RegistryID = reg.ScopeKey()
	}
	return target
}

// destFor resolves the most specific precompiled static plan for a destination
// — tool over registry over base — together with the principal-scoped entries
// that still have to be filtered against the caller. The entries stay in three
// separate lists so nothing is allocated to join them.
func (p *PolicyPlans) destFor(
	target policydomain.MCPTarget,
) (*appplugins.StagePlan, [3][]scopedEntry, map[string]struct{}) {
	static := p.base
	lists := [3][]scopedEntry{p.anyDest, nil, nil}
	var toolStaticSlugs map[string]struct{}
	if dest, ok := p.byRegistry[target.RegistryID]; ok {
		static = dest.static
		lists[1] = dest.principal
	}
	if dest, ok := p.byTool[target]; ok {
		static = dest.static
		// Already merged at build time: the registry entries this tool still has
		// to weigh, minus the ones a tool-level policy replaced outright.
		lists[1] = dest.lower
		lists[2] = dest.principal
		toolStaticSlugs = dest.staticSlugs
	}
	return static, lists, toolStaticSlugs
}

func emptyLists(lists [3][]scopedEntry) bool {
	return len(lists[0])+len(lists[1])+len(lists[2]) == 0
}

// planWith unions into static the principal-scoped plans the caller matches.
// The statically scoped policies of the destination are already folded into
// static, so only these lists are walked.
func (p *PolicyPlans) planWith(
	target policydomain.MCPTarget,
	lists [3][]scopedEntry,
	static *appplugins.StagePlan,
	caller policydomain.MCPCaller,
	toolStaticSlugs map[string]struct{},
) *appplugins.StagePlan {
	// Which slugs a tool-level policy already covers for this caller. Only then
	// does a registry-level policy of the same slug stand down: a tool policy
	// that does not match this caller replaces nothing.
	var toolWon map[string]struct{}
	for i := range lists[2] {
		if ok, _ := lists[2][i].scope.Matches(target, caller); ok {
			if toolWon == nil {
				toolWon = make(map[string]struct{}, len(lists[2]))
			}
			toolWon[lists[2][i].ref.Slug] = struct{}{}
		}
	}

	var matched []*appplugins.StagePlan
	for level, list := range lists {
		for i := range list {
			// level 1 is the registry; it yields to the tool for that slug.
			if level == 1 {
				slug := list[i].ref.Slug
				if inSlugs(toolWon, slug) || inSlugs(toolStaticSlugs, slug) {
					continue
				}
			}
			if ok, _ := list[i].scope.Matches(target, caller); ok {
				matched = append(matched, list[i].plan)
			}
		}
	}
	if len(matched) == 0 {
		return static
	}
	return static.Union(matched...)
}

// callerFor projects the principal only when some scoped policy can read it.
// A consumer scoped purely by destination never pays for the group list.
func (p *PolicyPlans) callerFor(principal *identity.Principal) policydomain.MCPCaller {
	if !p.hasPrincipal {
		return policydomain.MCPCaller{}
	}
	return callerOf(principal)
}

// callerOf projects the principal the scope matcher reads, and is the one
// place that decides whether the group dimension gates for this caller.
//
// The decision is an allow-list of one method, never a deny-list: only an api
// key makes the principal inert, because there the caller is the application
// and no identity provider is in the loop. A nil principal, a bearer token
// whose issuer emits no groups claim, mTLS, and the legacy undifferentiated
// MethodJWT all keep gating. The repo already writes that convention down for
// MethodJWT (identity/principal.go): "a principal that still carries it must
// keep facing the checks it faced before, never fall through to a permissive
// default". Reading the rule as "no groups in the claim means inert" would
// turn one misconfigured identity provider into a gateway-wide bypass of
// every group check (RUN-1621, rule 5.2).
func callerOf(principal *identity.Principal) policydomain.MCPCaller {
	if principal == nil {
		return policydomain.MCPCaller{}
	}
	return policydomain.MCPCaller{
		Groups:         principal.Groups(),
		PrincipalInert: principal.Method == identity.MethodAPIKey,
	}
}

func hasAnyStage(plan *appplugins.StagePlan) bool {
	for _, stage := range planStages {
		if plan.Has(stage) {
			return true
		}
	}
	return false
}

func concatPolicies(lists ...[]*policydomain.Policy) []*policydomain.Policy {
	size := 0
	for _, list := range lists {
		size += len(list)
	}
	out := make([]*policydomain.Policy, 0, size)
	for _, list := range lists {
		out = append(out, list...)
	}
	return out
}
