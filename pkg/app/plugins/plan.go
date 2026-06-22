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

package plugins

import (
	"log/slog"
	"sort"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

type StagePlan struct {
	byStage map[policy.Stage][]chainEntry
	batches map[policy.Stage][][]chainEntry
}

var planStages = [...]policy.Stage{
	policy.StagePreRequest,
	policy.StagePostRequest,
	policy.StagePreResponse,
	policy.StagePostResponse,
}

func NewStagePlan(reg Registry, policies []*policy.Policy, logger *slog.Logger) *StagePlan {
	plan := &StagePlan{
		byStage: make(map[policy.Stage][]chainEntry, len(planStages)),
		batches: make(map[policy.Stage][][]chainEntry, len(planStages)),
	}
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
			mode:        pol.Mode.Normalize(),
			priority:    pol.Priority,
			parallel:    pol.Parallel,
			global:      pol.IsGlobal(),
			mutatesReq:  plugin.MutatesRequestBody(),
			mutatesResp: plugin.MutatesResponseBody(),
			mutatesMeta: plugin.MutatesMetadata(),
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
		plan.batches[stage] = groupBatches(entries, stage, logger)
	}
	return plan
}

func (p *StagePlan) Has(stage policy.Stage) bool {
	if p == nil {
		return false
	}
	return len(p.byStage[stage]) > 0
}

func (p *StagePlan) Blocks(stage policy.Stage) bool {
	if p == nil {
		return false
	}
	for _, entry := range p.byStage[stage] {
		if Blocks(entry.mode) {
			return true
		}
	}
	return false
}

func (p *StagePlan) entriesFor(stage policy.Stage) []chainEntry {
	if p == nil {
		return nil
	}
	return p.byStage[stage]
}

func (p *StagePlan) batchesFor(stage policy.Stage) [][]chainEntry {
	if p == nil {
		return nil
	}
	return p.batches[stage]
}

func groupBatches(entries []chainEntry, stage policy.Stage, logger *slog.Logger) [][]chainEntry {
	if len(entries) == 0 {
		return nil
	}
	sorted := append([]chainEntry(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.priority != b.priority {
			return a.priority < b.priority
		}
		if a.config.Slug != b.config.Slug {
			return a.config.Slug < b.config.Slug
		}
		return a.config.ID < b.config.ID
	})

	batches := make([][]chainEntry, 0, len(sorted))
	var current []chainEntry
	var usedReq, usedResp, usedMeta bool
	for i := range sorted {
		entry := sorted[i]
		if !entry.parallel {
			if len(current) > 0 {
				batches = append(batches, current)
				current = nil
				usedReq, usedResp, usedMeta = false, false, false
			}
			batches = append(batches, []chainEntry{entry})
			continue
		}
		if len(current) > 0 {
			samePriority := current[0].priority == entry.priority
			capability := ""
			if samePriority {
				switch {
				case entry.mutatesReq && usedReq:
					capability = "request_body"
				case entry.mutatesResp && usedResp:
					capability = "response_body"
				case entry.mutatesMeta && usedMeta:
					capability = "metadata"
				}
			}
			if !samePriority || capability != "" {
				if capability != "" && logger != nil {
					logger.Warn("plugin forced sequential: parallel batch capability cap exceeded",
						slog.String("stage", string(stage)),
						slog.String("slug", entry.config.Slug),
						slog.String("capability", capability))
				}
				batches = append(batches, current)
				current = nil
				usedReq, usedResp, usedMeta = false, false, false
			}
		}
		current = append(current, entry)
		usedReq = usedReq || entry.mutatesReq
		usedResp = usedResp || entry.mutatesResp
		usedMeta = usedMeta || entry.mutatesMeta
	}
	if len(current) > 0 {
		batches = append(batches, current)
	}
	return batches
}
