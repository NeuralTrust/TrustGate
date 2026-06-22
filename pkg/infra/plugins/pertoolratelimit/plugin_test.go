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

package pertoolratelimit

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlugin_Stages(t *testing.T) {
	p := New(nil, nil)
	assert.Equal(t, PluginName, p.Name())
	assert.Equal(t, "per_tool_rate_limiter", p.Name())
	assert.Equal(t, []policy.Stage{policy.StagePreResponse}, p.MandatoryStages())
	assert.Equal(t, []policy.Stage{policy.StagePreResponse}, p.SupportedStages())
	assert.Equal(t, []policy.Mode{policy.ModeEnforce}, p.SupportedModes())
}

func TestPlugin_New_Defaults(t *testing.T) {
	p := New(nil, nil)
	require.NotNil(t, p.now)
	assert.Nil(t, p.redis)
	assert.Nil(t, p.registry)
}

func TestPlugin_WithClock(t *testing.T) {
	fixed := time.Unix(1000, 0)
	p := New(nil, nil, WithClock(func() time.Time { return fixed }))
	assert.Equal(t, fixed, p.now())
}

func TestPlugin_Execute_Noop(t *testing.T) {
	p := New(nil, nil)
	res, err := p.Execute(context.Background(), appplugins.ExecInput{Stage: policy.StagePreResponse})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestPlugin_RateLimitTemplate(t *testing.T) {
	msg := fmt.Sprintf(rateLimitTemplate, "send_email", "call_1")
	assert.Contains(t, msg, "send_email")
	assert.Contains(t, msg, "call_1")
}

func run695Settings() map[string]any {
	return map[string]any{
		"scope": "consumer",
		"rules": []any{
			map[string]any{
				"tool": "execute_code*",
				"windows": []any{
					map[string]any{"duration": "1h", "max": 50},
				},
				"behavior": "inject_error_result",
			},
		},
		"behavior_default": "reject_response",
	}
}

func TestPlugin_ValidateConfig(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		wantErr  bool
	}{
		{
			name:     "valid RUN-695 config",
			settings: run695Settings(),
		},
		{
			name: "rule without behavior uses default",
			settings: map[string]any{
				"rules": []any{
					map[string]any{
						"tool":    "*",
						"windows": []any{map[string]any{"duration": "1m", "max": 5}},
					},
				},
			},
		},
		{
			name: "empty rules",
			settings: map[string]any{
				"behavior_default": "reject_response",
				"rules":            []any{},
			},
			wantErr: true,
		},
		{
			name: "missing rules",
			settings: map[string]any{
				"behavior_default": "reject_response",
			},
			wantErr: true,
		},
		{
			name: "empty tool",
			settings: map[string]any{
				"rules": []any{
					map[string]any{
						"tool":    "",
						"windows": []any{map[string]any{"duration": "1m", "max": 5}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "bad glob pattern",
			settings: map[string]any{
				"rules": []any{
					map[string]any{
						"tool":    "[",
						"windows": []any{map[string]any{"duration": "1m", "max": 5}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "no windows",
			settings: map[string]any{
				"rules": []any{
					map[string]any{
						"tool":    "send_email",
						"windows": []any{},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "unparseable duration",
			settings: map[string]any{
				"rules": []any{
					map[string]any{
						"tool":    "send_email",
						"windows": []any{map[string]any{"duration": "abc", "max": 5}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "zero duration",
			settings: map[string]any{
				"rules": []any{
					map[string]any{
						"tool":    "send_email",
						"windows": []any{map[string]any{"duration": "0s", "max": 5}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "fractional duration",
			settings: map[string]any{
				"rules": []any{
					map[string]any{
						"tool":    "send_email",
						"windows": []any{map[string]any{"duration": "1500ms", "max": 5}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "max not positive",
			settings: map[string]any{
				"rules": []any{
					map[string]any{
						"tool":    "send_email",
						"windows": []any{map[string]any{"duration": "1m", "max": 0}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "bad behavior",
			settings: map[string]any{
				"rules": []any{
					map[string]any{
						"tool":     "send_email",
						"windows":  []any{map[string]any{"duration": "1m", "max": 5}},
						"behavior": "explode",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "strip behavior rejected",
			settings: map[string]any{
				"rules": []any{
					map[string]any{
						"tool":     "send_email",
						"windows":  []any{map[string]any{"duration": "1m", "max": 5}},
						"behavior": "strip_tool_from_request",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "strip behavior_default rejected",
			settings: map[string]any{
				"behavior_default": "strip_tool_from_request",
				"rules": []any{
					map[string]any{
						"tool":    "send_email",
						"windows": []any{map[string]any{"duration": "1m", "max": 5}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "bad scope",
			settings: map[string]any{
				"scope": "tenant",
				"rules": []any{
					map[string]any{
						"tool":    "send_email",
						"windows": []any{map[string]any{"duration": "1m", "max": 5}},
					},
				},
			},
			wantErr: true,
		},
	}

	p := New(nil, nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.ValidateConfig(tt.settings)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestPlugin_AppearsInCatalog(t *testing.T) {
	reg := appplugins.NewRegistry()
	require.NoError(t, reg.Register(New(nil, nil)))

	catalog := appplugins.NewCatalogService(reg).Catalog()

	var entry appplugins.CatalogEntry
	found := false
	for _, group := range catalog.Groups {
		for _, item := range group.Items {
			if item.Slug == PluginName {
				entry = item
				found = true
			}
		}
	}
	require.Truef(t, found, "slug %q missing from catalog", PluginName)
	assert.Equal(t, []policy.Stage{policy.StagePreResponse}, entry.SupportedStages)
	assert.Equal(t, []policy.Mode{policy.ModeEnforce}, entry.SupportedModes)
	assert.NotEmpty(t, entry.SettingsSchema.Fields)
}
