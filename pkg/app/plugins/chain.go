package plugins

import (
	"sort"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
)

type chainEntry struct {
	plugin Plugin
	config policy.Plugin
}

func buildStageChain(reg Registry, policies []*policy.Policy, stage policy.Stage) []chainEntry {
	entries := make([]chainEntry, 0)
	seen := make(map[string]struct{})

	for _, pol := range policies {
		if pol == nil {
			continue
		}
		for _, cfg := range pol.Plugins {
			if !cfg.Enabled {
				continue
			}
			if _, dup := seen[cfg.Name]; dup {
				continue
			}
			plugin, ok := reg.Get(cfg.Name)
			if !ok {
				continue
			}
			if !pluginRunsAtStage(plugin, stage) {
				continue
			}
			seen[cfg.Name] = struct{}{}
			entries = append(entries, chainEntry{plugin: plugin, config: cfg})
		}
	}

	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].config.Priority < entries[j].config.Priority
	})
	return entries
}

func parallelBatch(entries []chainEntry, i int) []chainEntry {
	if !entries[i].config.Parallel {
		return entries[i : i+1]
	}
	j := i
	for j < len(entries) &&
		entries[j].config.Parallel &&
		entries[j].config.Priority == entries[i].config.Priority {
		j++
	}
	return entries[i:j]
}
