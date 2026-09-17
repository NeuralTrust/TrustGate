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

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// Warner computes the non-blocking warnings the Admin API returns with a
// policy write. Scoped policies are additive to the unscoped plan (the slug
// override only applies among unscoped policies), so a consumer that already
// runs the same plugin without scope executes it twice. Two configurations of
// one plugin can be intended, hence a warning rather than an error.
//
//go:generate mockery --name=Warner --dir=. --output=./mocks --filename=policy_warner_mock.go --case=underscore --with-expecter
type Warner interface {
	// Overlaps lists the consumers reached by p (its associations, or every
	// MCP consumer of the gateway when p is global) that already run p's plugin
	// without an mcp_scope. A policy without scope never warns.
	Overlaps(ctx context.Context, p *domain.Policy) ([]string, error)
	// OverlapsOnAttach is Overlaps restricted to the consumer a policy has
	// just been attached to.
	OverlapsOnAttach(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, policyID ids.PolicyID) ([]string, error)
}

var _ Warner = (*warner)(nil)

type warner struct {
	policies  domain.Repository
	consumers consumerdomain.Reader
}

// NewWarner builds a Warner over the policy and consumer read models.
func NewWarner(policies domain.Repository, consumers consumerdomain.Reader) Warner {
	return &warner{policies: policies, consumers: consumers}
}

func (w *warner) Overlaps(ctx context.Context, p *domain.Policy) ([]string, error) {
	if p == nil || p.MCPScope == nil {
		return nil, nil
	}
	reach, unreached, err := w.reach(ctx, p)
	if err != nil {
		return nil, err
	}
	warnings, err := w.overlaps(ctx, p, reach)
	if err != nil {
		return nil, err
	}
	return appendUnreachedWarning(warnings, unreached), nil
}

// appendUnreachedWarning reports the non-MCP consumers a global policy stopped
// running on the moment it gained a scope. Scoped policies never enter the
// plan of an LLM or A2A consumer, so adding mcp_scope to a global policy
// silently takes it off that traffic; an operator has to hear about it.
func appendUnreachedWarning(warnings []string, unreached int) []string {
	if unreached == 0 {
		return warnings
	}
	return append(warnings, fmt.Sprintf(
		"policy is global and scoped to MCP: it no longer runs on %d non-MCP consumer(s) of the gateway",
		unreached))
}

func (w *warner) OverlapsOnAttach(ctx context.Context, gatewayID ids.GatewayID, consumerID ids.ConsumerID, policyID ids.PolicyID) ([]string, error) {
	p, err := w.policies.FindByID(ctx, policyID)
	if err != nil {
		return nil, err
	}
	if p.GatewayID != gatewayID || p.MCPScope == nil {
		return nil, nil
	}
	return w.overlaps(ctx, p, []ids.ConsumerID{consumerID})
}

// reach returns the consumers whose MCP plan p takes part in, and how many
// consumers of the gateway it no longer reaches at all. A global policy reaches
// every MCP consumer; LLM and A2A consumers never run a scoped policy, so they
// are left out and counted as unreached. A non-global policy cannot be attached
// to a non-MCP consumer in the first place, so it never has any.
func (w *warner) reach(ctx context.Context, p *domain.Policy) ([]ids.ConsumerID, int, error) {
	if !p.Global {
		return p.ConsumerIDs, 0, nil
	}
	consumers, err := w.consumers.ListByGateway(ctx, p.GatewayID)
	if err != nil {
		return nil, 0, err
	}
	out := make([]ids.ConsumerID, 0, len(consumers))
	unreached := 0
	for _, c := range consumers {
		if c == nil {
			continue
		}
		if c.Type != consumerdomain.TypeMCP {
			unreached++
			continue
		}
		out = append(out, c.ID)
	}
	return out, unreached, nil
}

func (w *warner) overlaps(ctx context.Context, p *domain.Policy, reach []ids.ConsumerID) ([]string, error) {
	if len(reach) == 0 {
		return nil, nil
	}
	policies, err := w.policies.ListByGateway(ctx, p.GatewayID)
	if err != nil {
		return nil, err
	}
	unscopedGlobal := false
	unscopedOn := make(map[ids.ConsumerID]struct{})
	for _, q := range policies {
		if q == nil || q.ID == p.ID || q.Slug != p.Slug || q.MCPScope != nil || !q.Enabled {
			continue
		}
		if q.Global {
			unscopedGlobal = true
			continue
		}
		for _, cid := range q.ConsumerIDs {
			unscopedOn[cid] = struct{}{}
		}
	}
	if !unscopedGlobal && len(unscopedOn) == 0 {
		return nil, nil
	}
	seen := make(map[ids.ConsumerID]struct{}, len(reach))
	var warnings []string
	for _, cid := range reach {
		if _, dup := seen[cid]; dup {
			continue
		}
		seen[cid] = struct{}{}
		if _, ok := unscopedOn[cid]; ok || unscopedGlobal {
			warnings = append(warnings, fmt.Sprintf("consumer %s already runs plugin %s without scope", cid, p.Slug))
		}
	}
	sort.Strings(warnings)
	return warnings, nil
}
