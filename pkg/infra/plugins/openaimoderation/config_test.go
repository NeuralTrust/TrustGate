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

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

func TestParseConfig(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		settings   map[string]any
		wantErr    bool
		wantModel  string
		wantStages []string
	}{
		{
			name:       "defaults applied",
			settings:   map[string]any{"api_key": "key"},
			wantModel:  defaultModel,
			wantStages: []string{stagePreRequest, stagePreResponse},
		},
		{
			name:       "explicit values preserved",
			settings:   map[string]any{"api_key": "key", "model": "text-moderation-stable", "stages": []string{stagePreRequest}},
			wantModel:  "text-moderation-stable",
			wantStages: []string{stagePreRequest},
		},
		{
			name:     "missing api_key",
			settings: map[string]any{"model": "m"},
			wantErr:  true,
		},
		{
			name:     "blank api_key",
			settings: map[string]any{"api_key": "  "},
			wantErr:  true,
		},
		{
			name:     "invalid stage rejected",
			settings: map[string]any{"api_key": "key", "stages": []string{"post_request"}},
			wantErr:  true,
		},
		{
			name:     "threshold below zero rejected",
			settings: map[string]any{"api_key": "key", "thresholds": map[string]any{"hate": -0.1}},
			wantErr:  true,
		},
		{
			name:     "threshold above one rejected",
			settings: map[string]any{"api_key": "key", "thresholds": map[string]any{"hate": 1.5}},
			wantErr:  true,
		},
		{
			name:       "valid config with thresholds and categories",
			settings:   map[string]any{"api_key": "key", "categories": []string{"hate"}, "thresholds": map[string]any{"hate": 0.7}, "block_on_flagged": true},
			wantModel:  defaultModel,
			wantStages: []string{stagePreRequest, stagePreResponse},
		},
		{
			name:       "threshold bounds accepted",
			settings:   map[string]any{"api_key": "key", "thresholds": map[string]any{"hate": 0.0, "violence": 1.0}},
			wantModel:  defaultModel,
			wantStages: []string{stagePreRequest, stagePreResponse},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := parseConfig(tt.settings)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "openai_moderation:")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantModel, cfg.Model)
			assert.Equal(t, tt.wantStages, cfg.Stages)
		})
	}
}

func TestSelectsStage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		stages          []string
		wantPreRequest  bool
		wantPreResponse bool
	}{
		{name: "request only", stages: []string{stagePreRequest}, wantPreRequest: true, wantPreResponse: false},
		{name: "response only", stages: []string{stagePreResponse}, wantPreRequest: false, wantPreResponse: true},
		{name: "both", stages: []string{stagePreRequest, stagePreResponse}, wantPreRequest: true, wantPreResponse: true},
		{name: "neither", stages: nil, wantPreRequest: false, wantPreResponse: false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s := Settings{Stages: tt.stages}
			assert.Equal(t, tt.wantPreRequest, s.selectsStage(policy.StagePreRequest))
			assert.Equal(t, tt.wantPreResponse, s.selectsStage(policy.StagePreResponse))
		})
	}
}
