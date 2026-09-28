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

package openaimoderation

import "sort"

type aggregated struct {
	scores     map[string]float64
	flagged    map[string]bool
	anyFlagged bool
}

func aggregate(results []moderationResult) aggregated {
	agg := aggregated{scores: map[string]float64{}, flagged: map[string]bool{}}
	for _, r := range results {
		if r.Flagged {
			agg.anyFlagged = true
		}
		for cat, score := range r.CategoryScores {
			if score > agg.scores[cat] {
				agg.scores[cat] = score
			}
		}
		for cat, flagged := range r.Categories {
			if flagged {
				agg.flagged[cat] = true
			}
		}
	}
	return agg
}

func evaluate(cfg Settings, agg aggregated) []violation {
	categories := evaluationSet(cfg, agg)
	violations := make([]violation, 0, len(categories))
	for _, cat := range categories {
		score := agg.scores[cat]
		if threshold, ok := cfg.Thresholds[cat]; ok && score >= threshold {
			violations = append(violations, violation{Category: cat, Score: score, Threshold: threshold})
			continue
		}
		if cfg.BlockOnFlagged && agg.flagged[cat] {
			violations = append(violations, violation{Category: cat, Score: score})
		}
	}
	return violations
}

func evaluationSet(cfg Settings, agg aggregated) []string {
	if len(cfg.Categories) > 0 {
		seen := make(map[string]struct{}, len(cfg.Categories))
		set := make([]string, 0, len(cfg.Categories))
		for _, cat := range cfg.Categories {
			if _, ok := seen[cat]; ok {
				continue
			}
			seen[cat] = struct{}{}
			set = append(set, cat)
		}
		sort.Strings(set)
		return set
	}
	seen := make(map[string]struct{}, len(agg.scores)+len(agg.flagged))
	for cat := range agg.scores {
		seen[cat] = struct{}{}
	}
	for cat := range agg.flagged {
		seen[cat] = struct{}{}
	}
	set := make([]string, 0, len(seen))
	for cat := range seen {
		set = append(set, cat)
	}
	sort.Strings(set)
	return set
}

// missingKnownThreshold reports the first (sorted) thresholds key that is
// known for cfg.Model but absent from agg.scores - a gap in the moderation
// response, not a clean "below threshold". An unknown model, or a thresholds
// key that model does not recognise, is ignored here exactly like
// evaluate()'s own unknown-key tolerance: a policy saved before this
// category set existed must keep running unchanged. See
// azure_content_safety's evaluate for the same pattern.
func missingKnownThreshold(cfg Settings, agg aggregated) string {
	known, ok := categoriesForModel(cfg.Model)
	if !ok {
		return ""
	}
	names := make([]string, 0, len(cfg.Thresholds))
	for cat := range cfg.Thresholds {
		if _, isKnown := known[cat]; isKnown {
			names = append(names, cat)
		}
	}
	sort.Strings(names)
	for _, cat := range names {
		if _, present := agg.scores[cat]; !present {
			return cat
		}
	}
	return ""
}

func maxScore(agg aggregated) (string, float64) {
	categories := make([]string, 0, len(agg.scores))
	for cat := range agg.scores {
		categories = append(categories, cat)
	}
	sort.Strings(categories)

	var topCategory string
	var topScore float64
	for _, cat := range categories {
		if agg.scores[cat] > topScore {
			topScore = agg.scores[cat]
			topCategory = cat
		}
	}
	return topCategory, topScore
}
