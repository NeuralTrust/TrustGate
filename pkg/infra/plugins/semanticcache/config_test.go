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

package semanticcache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfig_Precedence(t *testing.T) {
	tests := []struct {
		name         string
		settings     map[string]any
		wantTTL      time.Duration
		wantProvider string
		wantModel    string
	}{
		{
			name: "legacy ttl string only",
			settings: map[string]any{
				"similarity_threshold": 0.8,
				"ttl":                  "1h",
				"embedding":            map[string]any{"provider": "nestedp", "model": "nestedm"},
			},
			wantTTL:      time.Hour,
			wantProvider: "nestedp",
			wantModel:    "nestedm",
		},
		{
			name: "ttl_seconds wins over ttl string",
			settings: map[string]any{
				"similarity_threshold": 0.8,
				"ttl_seconds":          3600,
				"ttl":                  "2h",
				"embedding":            map[string]any{"provider": "nestedp", "model": "nestedm"},
			},
			wantTTL:      time.Hour,
			wantProvider: "nestedp",
			wantModel:    "nestedm",
		},
		{
			name: "nested embedding only",
			settings: map[string]any{
				"similarity_threshold": 0.8,
				"embedding":            map[string]any{"provider": "nestedp", "model": "nestedm", "api_key": "k"},
			},
			wantTTL:      defaultTTLSeconds * time.Second,
			wantProvider: "nestedp",
			wantModel:    "nestedm",
		},
		{
			name: "flattened wins over nested",
			settings: map[string]any{
				"similarity_threshold": 0.8,
				"embedding_provider":   "flatp",
				"embedding_model":      "flatm",
				"embedding":            map[string]any{"provider": "nestedp", "model": "nestedm"},
			},
			wantTTL:      defaultTTLSeconds * time.Second,
			wantProvider: "flatp",
			wantModel:    "flatm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseConfig(tt.settings)
			require.NoError(t, err)
			assert.Equal(t, tt.wantTTL, cfg.resolvedTTL())
			assert.Equal(t, tt.wantProvider, cfg.provider())
			assert.Equal(t, tt.wantModel, cfg.model())
		})
	}
}

func TestParseConfig_MissingAPIKeyValid(t *testing.T) {
	cfg, err := parseConfig(map[string]any{
		"similarity_threshold": 0.8,
		"embedding":            map[string]any{"provider": "openai", "model": "m"},
	})
	require.NoError(t, err)
	assert.Equal(t, "", cfg.embeddingDomainConfig().Credentials.APIKey)
}

func TestParseConfig_ValidationErrors(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
	}{
		{
			name:     "similarity threshold out of range",
			settings: map[string]any{"similarity_threshold": 1.5},
		},
		{
			name:     "invalid mode",
			settings: map[string]any{"similarity_threshold": 0.8, "mode": "bogus"},
		},
		{
			name:     "invalid scope",
			settings: map[string]any{"similarity_threshold": 0.8, "scope": "bogus"},
		},
		{
			name:     "invalid vector_store",
			settings: map[string]any{"similarity_threshold": 0.8, "vector_store": "bogus"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConfig(tt.settings)
			require.Error(t, err)
		})
	}
}

func TestParseConfig_EmptyDefaults(t *testing.T) {
	cfg, err := parseConfig(map[string]any{})
	require.NoError(t, err)

	assert.Equal(t, defaultTTLSeconds*time.Second, cfg.resolvedTTL())
	assert.Equal(t, defaultProvider, cfg.provider())
	assert.Equal(t, defaultModel, cfg.model())
	assert.Equal(t, modeSemantic, cfg.mode())
	assert.Equal(t, scopeConsumer, cfg.scope())
	assert.Equal(t, storeRedis, cfg.vectorStore())
	assert.True(t, cfg.skipIfTools())
	assert.True(t, cfg.cacheableStatus(200))
	assert.False(t, cfg.cacheableStatus(500))
}
