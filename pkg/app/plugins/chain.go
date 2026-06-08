package plugins

import (
	"sort"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
)

type chainEntry struct {
	plugin   Plugin
	config   policy.PluginConfig
	mode     policy.Mode
	priority int
	parallel bool
	global   bool
}

func buildStageChain(reg Registry, policies []*policy.Policy, stage policy.Stage) []chainEntry {
	entries := make([]chainEntry, 0, len(policies))
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
		if !isEffectiveStage(plugin, pol.Stages, stage) {
			continue
		}
		seen[id] = struct{}{}
		entries = append(entries, chainEntry{
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
			global:   pol.IsGlobal(),
		})
	}

	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].priority < entries[j].priority
	})
	return entries
}

func isEffectiveStage(p Plugin, selected []policy.Stage, stage policy.Stage) bool {
	for _, s := range p.MandatoryStages() {
		if s == stage {
			return true
		}
	}
	for _, s := range selected {
		if s == stage {
			return containsStage(p.SupportedStages(), stage)
		}
	}
	return false
}

func parallelBatch(entries []chainEntry, i int) []chainEntry {
	if !entries[i].parallel {
		return entries[i : i+1]
	}
	j := i
	for j < len(entries) &&
		entries[j].parallel &&
		entries[j].priority == entries[i].priority {
		j++
	}
	return entries[i:j]
}
