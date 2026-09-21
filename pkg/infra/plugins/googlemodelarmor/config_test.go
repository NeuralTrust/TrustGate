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

package googlemodelarmor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validSettings() map[string]any {
	return map[string]any{
		"project":  "proj",
		"location": "us-central1",
		"template": "tmpl",
	}
}

func TestParseConfigDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := parseConfig(validSettings())
	require.NoError(t, err)
	assert.ElementsMatch(t, allFilters, cfg.BlockOn)
	assert.Equal(t, sdpActionBlock, cfg.SDPAction)
}

func TestParseConfigPreservesExplicitBlockOn(t *testing.T) {
	t.Parallel()
	settings := validSettings()
	settings["block_on"] = []string{"sdp", "csam"}
	cfg, err := parseConfig(settings)
	require.NoError(t, err)
	assert.Equal(t, []string{"sdp", "csam"}, cfg.BlockOn)
}

func TestParseConfigValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(map[string]any)
		wantErr bool
	}{
		{name: "valid settings"},
		{
			name:    "missing project rejected",
			mutate:  func(s map[string]any) { delete(s, "project") },
			wantErr: true,
		},
		{
			name:    "blank location rejected",
			mutate:  func(s map[string]any) { s["location"] = "  " },
			wantErr: true,
		},
		{
			name:    "missing template rejected",
			mutate:  func(s map[string]any) { delete(s, "template") },
			wantErr: true,
		},
		{
			name:    "unknown block_on filter rejected",
			mutate:  func(s map[string]any) { s["block_on"] = []string{"sdp", "not_a_filter"} },
			wantErr: true,
		},
		{
			name:    "invalid sdp_action rejected",
			mutate:  func(s map[string]any) { s["sdp_action"] = "mask" },
			wantErr: true,
		},
		{
			name:   "explicit anonymize sdp_action accepted",
			mutate: func(s map[string]any) { s["sdp_action"] = "anonymize" },
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			settings := validSettings()
			if tt.mutate != nil {
				tt.mutate(settings)
			}
			_, err := parseConfig(settings)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestSettingsBlockOnSet(t *testing.T) {
	t.Parallel()
	s := Settings{BlockOn: []string{filterSDP, filterCSAM}}
	set := s.blockOnSet()
	assert.True(t, set[filterSDP])
	assert.True(t, set[filterCSAM])
	assert.False(t, set[filterRAI])
}
