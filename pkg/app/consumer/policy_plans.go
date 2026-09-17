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
	"strings"

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
	for target, statics := range staticByTool {
		registryStatics := staticByRegistry[target.RegistryID]
		plans.destForTool(target).static = appplugins.NewStagePlan(
			reg, concatPolicies(unscoped, registryStatics, statics), logger)
	}
	for target, dest := range plans.byTool {
		if dest.static == nil {
			dest.static = plans.staticForRegistry(target.RegistryID)
		}
	}
	return plans
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
	return p.planFor(targetOf(reg, nativeTool), principal)
}

// Explain returns the very plan PlanFor returns for the same arguments, plus
// the ScopeDecision that says which scoped policies of the consumer matched
// the destination and caller and which were skipped, with the reason. It
// allocates for the decision, so the dispatcher only calls it when a span is
// recording. A nil receiver returns nil and an empty decision.
func (p *PolicyPlans) Explain(
	reg *registrydomain.Registry,
	nativeTool string,
	principal *identity.Principal,
) (*appplugins.StagePlan, ScopeDecision) {
	if p == nil {
		return nil, ScopeDecision{}
	}
	target := targetOf(reg, nativeTool)
	return p.planFor(target, principal), p.explain(target, principal)
}

func (p *PolicyPlans) explain(target policydomain.MCPTarget, principal *identity.Principal) ScopeDecision {
	decision := ScopeDecision{Evaluated: len(p.scoped)}
	if len(p.scoped) == 0 {
		return decision
	}
	caller := callerOf(principal)
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

func (p *PolicyPlans) planFor(target policydomain.MCPTarget, principal *identity.Principal) *appplugins.StagePlan {
	static := p.base
	var registryPrincipal, toolPrincipal []scopedEntry
	if dest, ok := p.byRegistry[target.RegistryID]; ok {
		static = dest.static
		registryPrincipal = dest.principal
	}
	if dest, ok := p.byTool[target]; ok {
		static = dest.static
		toolPrincipal = dest.principal
	}
	if len(p.anyDest) == 0 && len(registryPrincipal) == 0 && len(toolPrincipal) == 0 {
		return static
	}
	caller := callerOf(principal)
	var matched []*appplugins.StagePlan
	for _, list := range [3][]scopedEntry{p.anyDest, registryPrincipal, toolPrincipal} {
		for i := range list {
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

func callerOf(principal *identity.Principal) policydomain.MCPCaller {
	if principal == nil {
		return policydomain.MCPCaller{}
	}
	return policydomain.MCPCaller{
		Subject: principal.Subject,
		Email:   strings.ToLower(principal.Email()),
		Groups:  principal.Groups(),
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
