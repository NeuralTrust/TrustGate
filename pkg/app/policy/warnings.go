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

package policy

import (
	"context"
	"fmt"
	"sort"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

const (
	dormantWarning = "policy has an empty mcp_scope and runs nowhere; " +
		"set mcp_scope to null to run it everywhere"
	scopeBoundWarning = "policy scope names a registry or a tool: " +
		"it runs on MCP traffic only, never on the LLM or A2A plane"
	orphanWarning = "policy has no consumers and is not global: it runs nowhere"
)

// inertUnsafeGlobalWarning names the one promotion that is saved and then runs
// nowhere but MCP. A global policy skips the attach, which is where the same
// refusal is a 422, so without this the operator hears nothing at all
// (RUN-1621, task 5.7). It stays a warning: rule 7 decides on purpose not to
// refuse the promotion, because global with a scope is legitimate
// configuration that the config load already filters.
func inertUnsafeGlobalWarning(slug string) string {
	return fmt.Sprintf("policy is global and its scope narrows by group alone, but plugin %s has not opted into "+
		"running where the scope is inert: it runs on MCP traffic only, never on the LLM or A2A plane", slug)
}

func overlapWarning(consumerID ids.ConsumerID, slug string) string {
	return fmt.Sprintf("consumer %s already runs plugin %s without scope", consumerID, slug)
}

func coalescedOntoUnscopedWarning(consumerID ids.ConsumerID, slug string) string {
	return fmt.Sprintf("consumer %s is not an MCP consumer and already runs plugin %s without scope: "+
		"the scope is inert on that plane, so both collapse onto the same level and only the unscoped policy runs",
		consumerID, slug)
}

func collapsedLevelWarning(consumerID ids.ConsumerID, slug string) string {
	return fmt.Sprintf("consumer %s is not an MCP consumer and already runs plugin %s under another group-scoped policy: "+
		"the two are distinct levels in MCP but the same level here, "+
		"so the configuration is saved and neither of them runs on that plane",
		consumerID, slug)
}

// Warner computes the non-blocking warnings the Admin API returns with a
// policy write: the configuration is accepted, and the operator hears where it
// will and will not run.
//
// Two of them exist because an mcp_scope means different things on either side
// of the MCP boundary. A scope narrowing by group alone crosses into the LLM
// and A2A planes, where the group does not gate, so policies the level guard
// accepted as distinct land on one level and the load resolves the collision
// by dropping some of them (RUN-1621, rule 3.6). That resolution used to be
// visible only in a startup log.
//
//go:generate mockery --name=Warner --dir=. --output=./mocks --filename=policy_warner_mock.go --case=underscore --with-expecter
type Warner interface {
	// Overlaps lists what the write just configured that will not run as
	// written: a scope that reaches nothing, a policy attached to nobody, and
	// the consumers reached by p that already run p's plugin under another
	// policy of the same slug.
	Overlaps(ctx context.Context, p *domain.Policy) ([]string, error)
	// OverlapsOnAttach is the per-consumer half of Overlaps, restricted to the
	// consumer a policy has just been attached to.
	OverlapsOnAttach(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, policyID ids.PolicyID) ([]string, error)
}

var _ Warner = (*warner)(nil)

type warner struct {
	policies  domain.Repository
	consumers consumerdomain.Reader
	plugins   appplugins.Registry
}

// NewWarner builds a Warner over the policy and consumer read models and the
// plugin registry, which is what says whether a plugin still runs where the
// scope does not gate.
func NewWarner(policies domain.Repository, consumers consumerdomain.Reader, plugins appplugins.Registry) Warner {
	return &warner{policies: policies, consumers: consumers, plugins: plugins}
}

func (w *warner) Overlaps(ctx context.Context, p *domain.Policy) ([]string, error) {
	if p == nil {
		return nil, nil
	}
	warnings := w.reachWarnings(p)
	if p.MCPScope == nil || p.Dormant() || !p.Enabled {
		return warnings, nil
	}
	reach, err := w.reach(ctx, p)
	if err != nil {
		return nil, err
	}
	collisions, err := w.collisions(ctx, p, reach)
	if err != nil {
		return nil, err
	}
	return append(warnings, collisions...), nil
}

func (w *warner) OverlapsOnAttach(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, policyID ids.PolicyID) ([]string, error) {
	p, err := w.policies.FindByID(ctx, policyID)
	if err != nil {
		return nil, err
	}
	if p.GatewayID != gatewayID || p.MCPScope == nil || p.Dormant() || !p.Enabled {
		return nil, nil
	}
	c, err := w.consumers.FindByID(ctx, consumerID)
	if err != nil {
		return nil, err
	}
	return w.collisions(ctx, p, []reachedConsumer{{id: consumerID, mcp: isMCP(c)}})
}

// reachWarnings describes where p runs from p alone, without asking what else
// the gateway holds.
func (w *warner) reachWarnings(p *domain.Policy) []string {
	var out []string
	switch {
	case p.Dormant():
		out = append(out, dormantWarning)
	case p.MCPScope.HasDestination():
		out = append(out, scopeBoundWarning)
	case p.Global && p.Enabled && p.MCPScope.CrossesPlanes() && !appplugins.IsInertSafe(w.plugins, p.Slug):
		out = append(out, inertUnsafeGlobalWarning(p.Slug))
	}
	if !p.Global && len(p.ConsumerIDs) == 0 {
		out = append(out, orphanWarning)
	}
	return out
}

type reachedConsumer struct {
	id  ids.ConsumerID
	mcp bool
}

// reach returns the consumers whose plan p takes part in. All three consumer
// types are candidates: a scope narrowing by group alone runs on LLM and A2A
// traffic too, inert there, so leaving them out would hide exactly the
// collisions these warnings exist for. Only a scope naming a registry or a
// tool is still MCP-only, and that one drops the other two types.
func (w *warner) reach(ctx context.Context, p *domain.Policy) ([]reachedConsumer, error) {
	consumers, err := w.consumers.ListByGateway(ctx, p.GatewayID)
	if err != nil {
		return nil, err
	}
	var attached map[ids.ConsumerID]struct{}
	if !p.Global {
		attached = make(map[ids.ConsumerID]struct{}, len(p.ConsumerIDs))
		for _, cid := range p.ConsumerIDs {
			attached[cid] = struct{}{}
		}
	}
	crosses := p.MCPScope.CrossesPlanes()
	out := make([]reachedConsumer, 0, len(consumers))
	for _, c := range consumers {
		if c == nil {
			continue
		}
		if attached != nil {
			if _, ok := attached[c.ID]; !ok {
				continue
			}
		}
		if !isMCP(c) && !crosses {
			continue
		}
		out = append(out, reachedConsumer{id: c.ID, mcp: isMCP(c)})
	}
	return out, nil
}

// collisions reports, per reached consumer, the other policy of the same slug
// that already runs there and what the load will do about it. Outside MCP the
// answer is never "both run": an unscoped policy of the same slug wins over
// the scoped one, and two group-scoped ones cancel each other out.
func (w *warner) collisions(ctx context.Context, p *domain.Policy, reach []reachedConsumer) ([]string, error) {
	if len(reach) == 0 {
		return nil, nil
	}
	policies, err := w.policies.ListByGateway(ctx, p.GatewayID)
	if err != nil {
		return nil, err
	}
	unscoped := sameSlugRunsWhere(policies, p, func(q *domain.Policy) bool { return q.MCPScope == nil })
	crossing := sameSlugRunsWhere(policies, p, func(q *domain.Policy) bool { return q.MCPScope.CrossesPlanes() })
	if !unscoped.any() && !crossing.any() {
		return nil, nil
	}
	var warnings []string
	for _, c := range reach {
		switch {
		case unscoped.reaches(c.id) && c.mcp:
			warnings = append(warnings, overlapWarning(c.id, p.Slug))
		case unscoped.reaches(c.id):
			warnings = append(warnings, coalescedOntoUnscopedWarning(c.id, p.Slug))
		case !c.mcp && crossing.reaches(c.id):
			warnings = append(warnings, collapsedLevelWarning(c.id, p.Slug))
		}
	}
	sort.Strings(warnings)
	return warnings, nil
}

// sameSlugRuns is where a plugin already runs under a policy other than the
// one being written: everywhere in the gateway when one of them is global, on
// the listed consumers otherwise.
type sameSlugRuns struct {
	global    bool
	consumers map[ids.ConsumerID]struct{}
}

func (r sameSlugRuns) any() bool { return r.global || len(r.consumers) > 0 }

func (r sameSlugRuns) reaches(consumerID ids.ConsumerID) bool {
	if r.global {
		return true
	}
	_, ok := r.consumers[consumerID]
	return ok
}

// sameSlugRunsWhere collects the enabled policies of p's slug that match. A
// disabled policy occupies no level, the same exemption the load makes, so it
// neither wins a collision nor causes one.
func sameSlugRunsWhere(policies []*domain.Policy, p *domain.Policy, match func(*domain.Policy) bool) sameSlugRuns {
	out := sameSlugRuns{consumers: make(map[ids.ConsumerID]struct{})}
	for _, q := range policies {
		if q == nil || q.ID == p.ID || q.Slug != p.Slug || !q.Enabled || !match(q) {
			continue
		}
		if q.Global {
			out.global = true
			continue
		}
		for _, cid := range q.ConsumerIDs {
			out.consumers[cid] = struct{}{}
		}
	}
	return out
}

func isMCP(c *consumerdomain.Consumer) bool {
	return c != nil && c.Type == consumerdomain.TypeMCP
}
