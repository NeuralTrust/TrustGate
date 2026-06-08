package plugins

import (
	"sort"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
)

type StagePlan struct {
	byStage map[policy.Stage][]chainEntry
}

var planStages = [...]policy.Stage{
	policy.StagePreRequest,
	policy.StagePostRequest,
	policy.StagePreResponse,
	policy.StagePostResponse,
}

func NewStagePlan(reg Registry, policies []*policy.Policy) *StagePlan {
	plan := &StagePlan{byStage: make(map[policy.Stage][]chainEntry, len(planStages))}
	if reg == nil {
		return plan
	}
	seen := make(map[string]struct{}, len(policies))
	for _, pol := range policies {
		if pol == nil || !pol.Enabled {
			continue
		}
		id := pol.ID.String()
		if _, dup := seen[id]; dup {
			continue
		}
		plugin, ok := reg.Get(pol.Slug)
		if !ok {
			continue
		}
		seen[id] = struct{}{}
		entry := chainEntry{
			plugin: plugin,
			config: policy.PluginConfig{
				ID:       id,
				Slug:     pol.Slug,
				Name:     pol.Name,
				Settings: pol.Settings,
			},
			mode:     pol.Mode.Normalize(),
			priority: pol.Priority,
			parallel: pol.Parallel,
		}
		for _, stage := range planStages {
			if isEffectiveStage(plugin, pol.Stages, stage) {
				plan.byStage[stage] = append(plan.byStage[stage], entry)
			}
		}
	}
	for stage := range plan.byStage {
		entries := plan.byStage[stage]
		sort.SliceStable(entries, func(i, j int) bool {
			return entries[i].priority < entries[j].priority
		})
	}
	return plan
}

func (p *StagePlan) Has(stage policy.Stage) bool {
	if p == nil {
		return false
	}
	return len(p.byStage[stage]) > 0
}

func (p *StagePlan) entriesFor(stage policy.Stage) []chainEntry {
	if p == nil {
		return nil
	}
	return p.byStage[stage]
}
