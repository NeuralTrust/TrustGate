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

import "github.com/NeuralTrust/TrustGate/pkg/infra/metrics"

type moderationRequest struct {
	Model string            `json:"model"`
	Input []moderationInput `json:"input"`
}

type moderationInput struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type moderationResponse struct {
	ID      string             `json:"id"`
	Model   string             `json:"model"`
	Results []moderationResult `json:"results"`
}

type moderationResult struct {
	Flagged        bool               `json:"flagged"`
	Categories     map[string]bool    `json:"categories"`
	CategoryScores map[string]float64 `json:"category_scores"`
}

type ModerationData struct {
	Model             string             `json:"model,omitempty"`
	CategoryScores    map[string]float64 `json:"category_scores,omitempty"`
	MaxScore          float64            `json:"max_score"`
	MaxScoreCategory  string             `json:"max_score_category,omitempty"`
	FlaggedByOpenAI   bool               `json:"flagged_by_openai"`
	FlaggedCategories []violation        `json:"flagged_categories,omitempty"`
	Decision          string             `json:"decision,omitempty"`
}

type violation struct {
	Category  string  `json:"category"`
	Score     float64 `json:"score"`
	Threshold float64 `json:"threshold,omitempty"`
}

func setExtras(event *metrics.EventContext, data ModerationData) {
	if event == nil {
		return
	}
	event.SetExtras(data)
}

// recordScore surfaces the dominant moderation category on the metrics span so
// it feeds the analytics Security Engine breakdown. It no-ops when no category
// score was produced (e.g. fail-open or empty input).
func recordScore(event *metrics.EventContext, data ModerationData) {
	if event == nil || data.MaxScoreCategory == "" {
		return
	}
	event.SetScore(data.MaxScore, data.MaxScoreCategory)
}
