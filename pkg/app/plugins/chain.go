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
	"sort"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

type chainEntry struct {
	plugin       Plugin
	config       policy.PluginConfig
	mode         policy.Mode
	priority     int
	specificity  uint8
	parallel     bool
	global       bool
	mutatesReq   bool
	mutatesResp  bool
	mutatesMeta  bool
	readsContent bool
	local        bool
}

// rewritesAt reports whether the entry rewrites the content the given stage
// carries: the request body on the request stages, the response body on the
// response stages.
func (e chainEntry) rewritesAt(stage policy.Stage) bool {
	switch stage {
	case policy.StagePreResponse, policy.StagePostResponse:
		return e.mutatesResp
	default:
		return e.mutatesReq
	}
}

// onlyReadsAt reports whether the entry inspects content at the stage without
// rewriting it. Such an entry must run after the rewriters of its priority.
func (e chainEntry) onlyReadsAt(stage policy.Stage) bool {
	return e.readsContent && !e.rewritesAt(stage)
}

// rewritesOffBoxAt reports whether the entry rewrites the stage's content and
// did not opt in as a local rewriter, so it may send that content to a third
// party. Such an entry must run after the local rewriters of its priority.
func (e chainEntry) rewritesOffBoxAt(stage policy.Stage) bool {
	return e.rewritesAt(stage) && !e.local
}

func lessEntry(a, b chainEntry) bool {
	if a.priority != b.priority {
		return a.priority < b.priority
	}
	if a.specificity != b.specificity {
		return a.specificity > b.specificity
	}
	if a.config.Slug != b.config.Slug {
		return a.config.Slug < b.config.Slug
	}
	return a.config.ID < b.config.ID
}

// entrySpecificity flattens the scope tie-break to zero on an inert plane. The
// only scope that reaches such a plane narrows by group alone and scores 1,
// which sorted descending would place it ahead of the unscoped policies of its
// priority and change the first writer of the batch (RUN-1621, rule 4).
func entrySpecificity(scope *policy.MCPScope, flatSpecificity bool) uint8 {
	if flatSpecificity {
		return 0
	}
	return scope.Specificity()
}

func buildStageChain(reg Registry, policies []*policy.Policy, stage policy.Stage, flatSpecificity bool) []chainEntry {
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
			mode:         pol.Mode.Normalize(),
			priority:     pol.Priority,
			specificity:  entrySpecificity(pol.MCPScope, flatSpecificity),
			parallel:     pol.Parallel,
			global:       pol.IsGlobal(),
			mutatesReq:   plugin.MutatesRequestBody(),
			mutatesResp:  plugin.MutatesResponseBody(),
			mutatesMeta:  plugin.MutatesMetadata(),
			readsContent: IsContentReader(plugin),
			local:        RewritesLocally(plugin),
		})
	}

	sort.SliceStable(entries, func(i, j int) bool {
		return lessEntry(entries[i], entries[j])
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
