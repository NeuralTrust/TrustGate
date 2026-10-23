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

package proxy

import (
	"log/slog"
	"slices"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/google/uuid"
)

// groupBudgetPolicyID is the id a group budget's stage runs and is traced
// under. It is fixed, so every replica reports the same one, and it is never
// stored: no policy an admin writes can carry it.
var groupBudgetPolicyID = ids.From[ids.PolicyKind](uuid.MustParse("6b67622d-0000-4000-8000-000000000001"))

// groupBudgetPriority runs the stage ahead of every policy an admin writes,
// whose priority is never negative: a request its group cannot pay for is
// refused before a guardrail is paid to judge it.
const groupBudgetPriority = -1

// groupBudgetStage adds a group's budget to the policies of a store request
// made with a key of that group. The plugin is not in the gateway's registry,
// so no policy can name it; the stage compiles its own one-entry plan once,
// and a request joins it to its consumer's.
type groupBudgetStage struct {
	policy *policydomain.Policy
	plan   *appplugins.StagePlan
}

// WithGroupBudget holds every store request made with a group key whose
// group has a budget to that budget, through plugin (the key_group_budget
// stage). Without it no group budget is enforced.
func WithGroupBudget(plugin appplugins.Plugin) ForwarderOption {
	return func(f *forwarder) {
		f.groupBudget = newGroupBudgetStage(plugin, f.logger)
	}
}

func newGroupBudgetStage(plugin appplugins.Plugin, logger *slog.Logger) *groupBudgetStage {
	if plugin == nil {
		return nil
	}
	reg := appplugins.NewRegistry()
	if err := reg.Register(plugin); err != nil {
		if logger != nil {
			logger.Error("group budget stage not built: no group budget is enforced", slog.String("error", err.Error()))
		}
		return nil
	}
	pol := &policydomain.Policy{
		ID:       groupBudgetPolicyID,
		Name:     plugin.Name(),
		Slug:     plugin.Name(),
		Stages:   []policydomain.Stage{policydomain.StagePreRequest, policydomain.StagePostResponse},
		Priority: groupBudgetPriority,
		Enabled:  true,
		// The budget's own action decides whether a reached limit refuses the
		// request; the stage runs in enforce so that a refusal it returns is
		// one.
		Mode: policydomain.ModeEnforce,
	}
	return &groupBudgetStage{
		policy: pol,
		plan:   appplugins.NewInertStagePlan(reg, []*policydomain.Policy{pol}, logger),
	}
}

// extend returns the policies and plan req runs under: the consumer's, and
// the group budget's when req carries one. A consumer with no compiled plan
// is left as it is: the executor would rebuild it from the gateway's
// registry, which does not hold the stage. Store consumers always carry one.
func (s *groupBudgetStage) extend(
	req *infracontext.RequestContext,
	policies []*policydomain.Policy,
	plan *appplugins.StagePlan,
) ([]*policydomain.Policy, *appplugins.StagePlan) {
	if s == nil || req == nil || req.KeyGroupBudget == nil || plan == nil {
		return policies, plan
	}
	// The consumer's slice is shared with every request it serves.
	return append(slices.Clip(policies), s.policy), plan.Union(s.plan)
}
