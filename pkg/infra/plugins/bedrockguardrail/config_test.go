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

package bedrockguardrail

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfigDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := parseConfig(map[string]any{
		"guardrail_id": "gr-123",
		"credentials": map[string]any{
			"access_key_id":     "AKIA",
			"secret_access_key": "secret",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, defaultVersion, cfg.Version)
	assert.Equal(t, piiActionBlock, cfg.PIIAction)
	assert.Equal(t, defaultRegion, cfg.Credentials.AWSRegion)
}

func TestParseConfigSessionNameDefaultedForRole(t *testing.T) {
	t.Parallel()
	cfg, err := parseConfig(map[string]any{
		"guardrail_id": "gr-123",
		"credentials": map[string]any{
			"use_role": true,
			"role_arn": "arn:aws:iam::123456789012:role/bedrock",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, defaultSessionName, cfg.Credentials.SessionName)
}

func TestParseConfigValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		settings map[string]any
		wantErr  bool
	}{
		{
			name: "valid static credentials",
			settings: map[string]any{
				"guardrail_id": "gr-123",
				"credentials": map[string]any{
					"access_key_id":     "AKIA",
					"secret_access_key": "secret",
				},
			},
		},
		{
			name: "valid role credentials",
			settings: map[string]any{
				"guardrail_id": "gr-123",
				"credentials": map[string]any{
					"use_role": true,
					"role_arn": "arn:aws:iam::123456789012:role/bedrock",
				},
			},
		},
		{
			name: "missing guardrail_id rejected",
			settings: map[string]any{
				"credentials": map[string]any{
					"access_key_id":     "AKIA",
					"secret_access_key": "secret",
				},
			},
			wantErr: true,
		},
		{
			name: "blank guardrail_id rejected",
			settings: map[string]any{
				"guardrail_id": "  ",
				"credentials": map[string]any{
					"access_key_id":     "AKIA",
					"secret_access_key": "secret",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid pii_action rejected",
			settings: map[string]any{
				"guardrail_id": "gr-123",
				"pii_action":   "mask",
				"credentials": map[string]any{
					"access_key_id":     "AKIA",
					"secret_access_key": "secret",
				},
			},
			wantErr: true,
		},
		{
			name: "use_role without role_arn rejected",
			settings: map[string]any{
				"guardrail_id": "gr-123",
				"credentials": map[string]any{
					"use_role": true,
				},
			},
			wantErr: true,
		},
		{
			name: "access_key_id without secret_access_key rejected",
			settings: map[string]any{
				"guardrail_id": "gr-123",
				"credentials": map[string]any{
					"access_key_id": "AKIA",
				},
			},
			wantErr: true,
		},
		{
			name: "secret_access_key without access_key_id rejected",
			settings: map[string]any{
				"guardrail_id": "gr-123",
				"credentials": map[string]any{
					"secret_access_key": "secret",
				},
			},
			wantErr: true,
		},
		{
			name: "no credentials and no role rejected",
			settings: map[string]any{
				"guardrail_id": "gr-123",
				"credentials":  map[string]any{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseConfig(tt.settings)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
