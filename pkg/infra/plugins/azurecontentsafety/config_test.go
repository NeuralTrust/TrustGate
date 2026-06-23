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

package azurecontentsafety

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		settings       map[string]any
		wantErr        bool
		wantOutputType string
		wantCategories []string
	}{
		{
			name: "valid minimal config defaults output_type and categories",
			settings: map[string]any{
				"api_key":           "key",
				"endpoint":          "https://content.cognitiveservices.azure.com/contentsafety/text:analyze",
				"category_severity": map[string]any{CategoryHate: 4},
			},
			wantOutputType: OutputTypeFourSeverityLevels,
			wantCategories: supportedCategories,
		},
		{
			name: "blank api_key rejected",
			settings: map[string]any{
				"api_key":           "  ",
				"endpoint":          "https://content.azure.com",
				"category_severity": map[string]any{CategoryHate: 4},
			},
			wantErr: true,
		},
		{
			name: "missing endpoint rejected",
			settings: map[string]any{
				"api_key":           "key",
				"category_severity": map[string]any{CategoryHate: 4},
			},
			wantErr: true,
		},
		{
			name: "relative endpoint rejected",
			settings: map[string]any{
				"api_key":           "key",
				"endpoint":          "/contentsafety/text:analyze",
				"category_severity": map[string]any{CategoryHate: 4},
			},
			wantErr: true,
		},
		{
			name: "non-http endpoint rejected",
			settings: map[string]any{
				"api_key":           "key",
				"endpoint":          "ftp://content.azure.com",
				"category_severity": map[string]any{CategoryHate: 4},
			},
			wantErr: true,
		},
		{
			name: "endpoint missing host rejected",
			settings: map[string]any{
				"api_key":           "key",
				"endpoint":          "http://",
				"category_severity": map[string]any{CategoryHate: 4},
			},
			wantErr: true,
		},
		{
			name: "bad output_type rejected",
			settings: map[string]any{
				"api_key":           "key",
				"endpoint":          "https://content.azure.com",
				"output_type":       "TwoSeverityLevels",
				"category_severity": map[string]any{CategoryHate: 4},
			},
			wantErr: true,
		},
		{
			name: "explicit categories preserved",
			settings: map[string]any{
				"api_key":           "key",
				"endpoint":          "https://content.azure.com",
				"categories":        []any{CategoryHate, CategorySexual},
				"category_severity": map[string]any{CategoryHate: 4},
			},
			wantOutputType: OutputTypeFourSeverityLevels,
			wantCategories: []string{CategoryHate, CategorySexual},
		},
		{
			name: "unknown category rejected",
			settings: map[string]any{
				"api_key":           "key",
				"endpoint":          "https://content.azure.com",
				"categories":        []any{"Profanity"},
				"category_severity": map[string]any{CategoryHate: 4},
			},
			wantErr: true,
		},
		{
			name: "missing category_severity rejected",
			settings: map[string]any{
				"api_key":  "key",
				"endpoint": "https://content.azure.com",
			},
			wantErr: true,
		},
		{
			name: "empty category_severity rejected",
			settings: map[string]any{
				"api_key":           "key",
				"endpoint":          "https://content.azure.com",
				"category_severity": map[string]any{},
			},
			wantErr: true,
		},
		{
			name: "four scale odd threshold rejected",
			settings: map[string]any{
				"api_key":           "key",
				"endpoint":          "https://content.azure.com",
				"category_severity": map[string]any{CategoryHate: 3},
			},
			wantErr: true,
		},
		{
			name: "four scale out-of-range threshold rejected",
			settings: map[string]any{
				"api_key":           "key",
				"endpoint":          "https://content.azure.com",
				"category_severity": map[string]any{CategoryHate: 8},
			},
			wantErr: true,
		},
		{
			name: "eight scale out-of-range threshold rejected",
			settings: map[string]any{
				"api_key":           "key",
				"endpoint":          "https://content.azure.com",
				"output_type":       OutputTypeEightSeverityLevels,
				"category_severity": map[string]any{CategoryHate: 8},
			},
			wantErr: true,
		},
		{
			name: "eight scale odd threshold accepted",
			settings: map[string]any{
				"api_key":           "key",
				"endpoint":          "https://content.azure.com",
				"output_type":       OutputTypeEightSeverityLevels,
				"category_severity": map[string]any{CategoryHate: 5},
			},
			wantOutputType: OutputTypeEightSeverityLevels,
			wantCategories: supportedCategories,
		},
		{
			name: "unknown category_severity key rejected",
			settings: map[string]any{
				"api_key":           "key",
				"endpoint":          "https://content.azure.com",
				"category_severity": map[string]any{"Profanity": 4},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := parseConfig(tt.settings)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantOutputType, cfg.OutputType)
			assert.Equal(t, tt.wantCategories, cfg.Categories)
		})
	}
}

func TestSeverityBounds(t *testing.T) {
	t.Parallel()
	four := Settings{OutputType: OutputTypeFourSeverityLevels}
	minFour, maxFour := four.severityBounds()
	assert.Equal(t, SeverityFourMin, minFour)
	assert.Equal(t, SeverityFourMax, maxFour)

	eight := Settings{OutputType: OutputTypeEightSeverityLevels}
	minEight, maxEight := eight.severityBounds()
	assert.Equal(t, SeverityEightMin, minEight)
	assert.Equal(t, SeverityEightMax, maxEight)
}

func TestThresholdFor(t *testing.T) {
	t.Parallel()
	cfg := Settings{CategorySeverity: map[string]int{CategoryHate: 4}}
	assert.Equal(t, 4, cfg.thresholdFor(CategoryHate))
	assert.Equal(t, 0, cfg.thresholdFor(CategoryViolence))
}
