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
	// streamed is the pre_response list a streamed segment walks: the entries
	// that take part in per-segment inspection (streamParticipants), in
	// OrderStreamEntries order. finishStage always sets it, empty but non-nil
	// when no entry takes part; plans built without finishStage leave it nil
	// and the executor derives it on demand.
	streamed []chainEntry
}

var planStages = [...]policy.Stage{
	policy.StagePreRequest,
	policy.StagePostRequest,
	policy.StagePreResponse,
	policy.StagePostResponse,
}

// NewStagePlan compiles the policies into a per-stage plan for the MCP plane,
// where the scope gates and its specificity breaks ties at equal priority.
func NewStagePlan(reg Registry, policies []*policy.Policy, logger *slog.Logger) *StagePlan {
	return newStagePlan(reg, policies, logger, false)
}

// NewInertStagePlan compiles the policies into a per-stage plan for a plane
// where the scope does not gate. Every entry scores zero specificity, so
// adding a group to a policy's scope can no longer reorder the chain
// (RUN-1621, rule 4).
func NewInertStagePlan(reg Registry, policies []*policy.Policy, logger *slog.Logger) *StagePlan {
	return newStagePlan(reg, policies, logger, true)
}

func newStagePlan(reg Registry, policies []*policy.Policy, logger *slog.Logger, flatSpecificity bool) *StagePlan {
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
			mode:         pol.Mode.Normalize(),
			priority:     pol.Priority,
			specificity:  entrySpecificity(pol.MCPScope, flatSpecificity),
			parallel:     pol.Parallel,
			global:       pol.GatewayWide(),
			mutatesReq:   plugin.MutatesRequestBody(),
			mutatesResp:  plugin.MutatesResponseBody(),
			mutatesMeta:  plugin.MutatesMetadata(),
			readsContent: IsContentReader(plugin),
			local:        RewritesLocally(plugin),
		}
		for _, stage := range planStages {
			if isEffectiveStage(plugin, pol.Stages, stage) {
				plan.byStage[stage] = append(plan.byStage[stage], entry)
			}
		}
	}
	for stage := range plan.byStage {
		plan.finishStage(stage, plan.byStage[stage], logger)
	}
	return plan
}

// Union returns a plan holding the entries of p and of every extra plan,
// deduplicated by policy id and regrouped into batches under the same ordering
// NewStagePlan applies. It never consults the plugin Registry, so it is safe on
// the request path. Without extras it returns p itself.
func (p *StagePlan) Union(extra ...*StagePlan) *StagePlan {
	if len(extra) == 0 {
		return p
	}
	out := &StagePlan{
		byStage: make(map[policy.Stage][]chainEntry, len(planStages)),
		batches: make(map[policy.Stage][][]chainEntry, len(planStages)),
	}
	for _, stage := range planStages {
		merged := appendUniqueEntries(nil, p.entriesFor(stage))
		for _, other := range extra {
			merged = appendUniqueEntries(merged, other.entriesFor(stage))
		}
		if len(merged) == 0 {
			continue
		}
		out.finishStage(stage, merged, nil)
	}
	return out
}

func (p *StagePlan) finishStage(stage policy.Stage, entries []chainEntry, logger *slog.Logger) {
	sort.SliceStable(entries, func(i, j int) bool {
		return lessEntry(entries[i], entries[j])
	})
	p.byStage[stage] = entries
	p.batches[stage] = groupBatches(entries, stage, logger)
	if stage == policy.StagePreResponse {
		p.streamed = streamParticipants(OrderStreamEntries(entries))
	}
}

func appendUniqueEntries(dst, src []chainEntry) []chainEntry {
	for _, entry := range src {
		if containsEntry(dst, entry.config.ID) {
			continue
		}
		dst = append(dst, entry)
	}
	return dst
}

func containsEntry(entries []chainEntry, id string) bool {
	for i := range entries {
		if entries[i].config.ID == id {
			return true
		}
	}
	return false
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

// StreamPlan reports whether any entry of the stage opted into per-segment
// inspection *and* has it enabled, and yields the options that entry runs
// under. The stream guard is built only when it reports true, so a gateway
// whose policies do not participate pays nothing for the feature.
//
// The opt-in and its configuration are answered together because only the
// plugin can parse its own settings: split apart, a plan that says "yes" would
// hand the caller no head_chars and no on_error, and the caller would run on
// defaults an operator never asked for.
//
// The first participating entry that owns stream options wins. One stream
// carries one head gate, and the entries are already ordered by priority. A
// passive participant (StreamOptionsOwner returning false, such as a local
// rewriter) yields to any owner, whatever the order, and its own options are
// used only when it is the sole participant.
func (p *StagePlan) StreamPlan(stage policy.Stage) (bool, StreamOptions) {
	if p == nil {
		return false, StreamOptions{}
	}
	var (
		passive    StreamOptions
		hasPassive bool
	)
	for _, entry := range p.byStage[stage] {
		inspector, ok := streamInspector(entry.plugin)
		if !ok {
			continue
		}
		enabled, opts := inspector.StreamSettings(entry.config.Settings)
		if !enabled {
			continue
		}
		if !ownsStreamOptions(entry.plugin) {
			if !hasPassive {
				passive, hasPassive = opts, true
			}
			continue
		}
		return true, opts
	}
	if hasPassive {
		return true, passive
	}
	return false, StreamOptions{}
}

func (p *StagePlan) entriesFor(stage policy.Stage) []chainEntry {
	if p == nil {
		return nil
	}
	return p.byStage[stage]
}

// streamEntriesFor is the pre_response list in streamed order. It is nil-safe
// and falls back to deriving the order for a plan that did not precompute it.
func (p *StagePlan) streamEntriesFor() []chainEntry {
	if p == nil {
		return nil
	}
	if p.streamed != nil {
		return p.streamed
	}
	return streamParticipants(OrderStreamEntries(p.byStage[policy.StagePreResponse]))
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
		return lessEntry(sorted[i], sorted[j])
	})

	sorted = orderByContentFlow(sorted, stage)

	batches := make([][]chainEntry, 0, len(sorted))
	var current []chainEntry
	var usedReq, usedResp, usedMeta, hasRewriter bool
	for i := range sorted {
		entry := sorted[i]
		if !entry.parallel {
			if len(current) > 0 {
				batches = append(batches, current)
				current = nil
				usedReq, usedResp, usedMeta, hasRewriter = false, false, false, false
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
			// A pure reader never shares a batch with a rewriter of its
			// priority: a batch runs on isolated copies, so it would judge the
			// original content (RUN-1693).
			readerAfterRewriter := samePriority && hasRewriter && entry.onlyReadsAt(stage)
			if !samePriority || capability != "" || readerAfterRewriter {
				if capability != "" && logger != nil {
					logger.Warn("plugin forced sequential: parallel batch capability cap exceeded",
						slog.String("stage", string(stage)),
						slog.String("slug", entry.config.Slug),
						slog.String("capability", capability))
				}
				batches = append(batches, current)
				current = nil
				usedReq, usedResp, usedMeta, hasRewriter = false, false, false, false
			}
		}
		current = append(current, entry)
		usedReq = usedReq || entry.mutatesReq
		usedResp = usedResp || entry.mutatesResp
		usedMeta = usedMeta || entry.mutatesMeta
		hasRewriter = hasRewriter || entry.rewritesAt(stage)
	}
	if len(current) > 0 {
		batches = append(batches, current)
	}
	return batches
}

// streamParticipants keeps the entries that take part in per-segment
// inspection: their plugin implements StreamInspector and their settings opt
// in. An entry that opted out has nothing to say about a block, yet walking it
// cost a span with no decision on every stream (RUN-1745 F5), could leave the
// stream's per-response instruments to an entry that records none, and let a
// policy whose settings no longer parse fail every block of a stream another
// policy opted into (F8). The opt-in reads only the policy's settings, so it
// is answered once when the plan is built. The result is never nil.
func streamParticipants(entries []chainEntry) []chainEntry {
	out := make([]chainEntry, 0, len(entries))
	for _, entry := range entries {
		inspector, ok := streamInspector(entry.plugin)
		if !ok {
			continue
		}
		if enabled, _ := inspector.StreamSettings(entry.config.Settings); enabled {
			out = append(out, entry)
		}
	}
	return out
}

// OrderStreamEntries returns the pre_response entries in the order a streamed
// segment walks them: the same content-flow rule batches use, so a reader
// (openai_moderation) or a remote guard (bedrock_guardrail) inspects a segment
// only after the local rewriters of its priority have masked it. Entries must
// already be in lessEntry order. The result is a new slice, deterministic and
// stable; priorities are never crossed.
func OrderStreamEntries(entries []chainEntry) []chainEntry {
	return orderByContentFlow(entries, policy.StagePreResponse)
}

// orderByContentFlow reorders each run of consecutive parallel entries that
// share a priority so that content reaches a third party only after every local
// rewrite of that priority:
//
//   - the pure content readers move after everything else (RUN-1693);
//   - among the rest, the slots the rewriters hold are refilled with the local
//     rewriters (RewritesLocally) first and then the rewriters that may send the
//     content off the box (RUN-1745). Entries that neither rewrite nor read keep
//     their exact place.
//
// The sort is stable, so the tie-break (specificity, slug, id) still decides the
// order inside each group. A run with no rewriter is left exactly as it was.
// Two rewriters of one stage always claim the same body, so the batch planner
// already runs them one after the other and the reorder adds no sequential
// step. Priorities are never crossed.
func orderByContentFlow(entries []chainEntry, stage policy.Stage) []chainEntry {
	out := make([]chainEntry, 0, len(entries))
	for i := 0; i < len(entries); {
		j := i + 1
		if entries[i].parallel {
			for j < len(entries) && entries[j].parallel && entries[j].priority == entries[i].priority {
				j++
			}
		}
		run := entries[i:j]
		hasRewriter := false
		for _, e := range run {
			hasRewriter = hasRewriter || e.rewritesAt(stage)
		}
		if !hasRewriter {
			out = append(out, run...)
			i = j
			continue
		}
		var head, readers, local, offBox []chainEntry
		var slots []int
		for _, e := range run {
			switch {
			case e.onlyReadsAt(stage):
				readers = append(readers, e)
				continue
			case e.rewritesOffBoxAt(stage):
				offBox = append(offBox, e)
				slots = append(slots, len(head))
			case e.rewritesAt(stage):
				local = append(local, e)
				slots = append(slots, len(head))
			}
			head = append(head, e)
		}
		for k, e := range append(local, offBox...) {
			head[slots[k]] = e
		}
		out = append(out, head...)
		out = append(out, readers...)
		i = j
	}
	return out
}
