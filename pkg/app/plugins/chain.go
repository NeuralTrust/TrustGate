package plugins

import (
	"sort"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
)

type chainEntry struct {
	plugin   Plugin
	config   policy.PluginConfig
	priority int
	parallel bool
}

func buildStageChain(reg Registry, policies []*policy.Policy, stage policy.Stage) []chainEntry {
	entries := make([]chainEntry, 0)
	seen := make(map[string]struct{})

	for _, pol := range policies {
		if pol == nil || !pol.Enabled {
			continue
		}
		if _, dup := seen[pol.ID.String()]; dup {
			continue
		}
		plugin, ok := reg.Get(pol.Slug)
		if !ok {
			continue
		}
		if !containsStage(EffectiveStages(plugin, pol.Stages), stage) {
			continue
		}
		seen[pol.ID.String()] = struct{}{}
		entries = append(entries, chainEntry{
			plugin: plugin,
			config: policy.PluginConfig{
				ID:       pol.ID.String(),
				Slug:     pol.Slug,
				Name:     pol.Name,
				Settings: pol.Settings,
			},
			priority: pol.Priority,
			parallel: pol.Parallel,
		})
	}

	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].priority < entries[j].priority
	})
	return entries
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
