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

package prompttemplate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func injectOnly(content string) map[string]any {
	return map[string]any{
		"inject_templates": []any{
			map[string]any{"id": "t1", "content": content},
		},
	}
}

func namedTemplateConfig() map[string]any {
	return map[string]any{
		"named_templates": []any{
			map[string]any{
				"name": "support-bot",
				"versions": []any{
					map[string]any{
						"version": "v1",
						"labels":  []any{"stable"},
						"content": "answer as {{persona}}",
						"required_variables": map[string]any{
							"persona": map[string]any{"type": "string"},
						},
					},
				},
			},
		},
		"default_label": "stable",
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		wantErr  bool
	}{
		{
			name:     "defaults applied with single inject",
			settings: injectOnly("hello {{tenant}}"),
		},
		{
			name: "mustache engine accepted",
			settings: map[string]any{
				"template_engine":  "mustache",
				"inject_templates": []any{map[string]any{"id": "t1", "content": "hi"}},
			},
		},
		{
			name: "jinja2_subset rejected",
			settings: map[string]any{
				"template_engine":  "jinja2_subset",
				"inject_templates": []any{map[string]any{"id": "t1", "content": "hi"}},
			},
			wantErr: true,
		},
		{
			name: "unknown engine rejected",
			settings: map[string]any{
				"template_engine":  "handlebars",
				"inject_templates": []any{map[string]any{"id": "t1", "content": "hi"}},
			},
			wantErr: true,
		},
		{
			name:     "valid named template",
			settings: namedTemplateConfig(),
		},
		{
			name: "context_variables header and jwt_claim accepted",
			settings: map[string]any{
				"context_variables": map[string]any{
					"tenant":    map[string]any{"source": "header", "name": "X-Tenant-Id"},
					"user_role": map[string]any{"source": "jwt_claim", "name": "role"},
				},
				"inject_templates": []any{map[string]any{"id": "t1", "content": "{{tenant}} {{user_role}}"}},
			},
		},
		{
			name: "consumer_attribute source rejected",
			settings: map[string]any{
				"context_variables": map[string]any{
					"tier": map[string]any{"source": "consumer_attribute", "name": "tier"},
				},
				"inject_templates": []any{map[string]any{"id": "t1", "content": "hi"}},
			},
			wantErr: true,
		},
		{
			name: "bad context variable source rejected",
			settings: map[string]any{
				"context_variables": map[string]any{
					"tier": map[string]any{"source": "query", "name": "tier"},
				},
				"inject_templates": []any{map[string]any{"id": "t1", "content": "hi"}},
			},
			wantErr: true,
		},
		{
			name: "bad on_missing_context_variable rejected",
			settings: map[string]any{
				"on_missing_context_variable": "errors",
				"inject_templates":            []any{map[string]any{"id": "t1", "content": "hi"}},
			},
			wantErr: true,
		},
		{
			name: "bad on_missing_client_variable rejected",
			settings: map[string]any{
				"on_missing_client_variable": "skip_injection",
				"inject_templates":           []any{map[string]any{"id": "t1", "content": "hi"}},
			},
			wantErr: true,
		},
		{
			name: "blank context variable name rejected",
			settings: map[string]any{
				"context_variables": map[string]any{
					"tier": map[string]any{"source": "header", "name": "  "},
				},
				"inject_templates": []any{map[string]any{"id": "t1", "content": "hi"}},
			},
			wantErr: true,
		},
		{
			name:     "neither inject nor named rejected",
			settings: map[string]any{},
			wantErr:  true,
		},
		{
			name:     "empty inject content rejected",
			settings: injectOnly("   "),
			wantErr:  true,
		},
		{
			name: "blank inject id rejected",
			settings: map[string]any{
				"inject_templates": []any{map[string]any{"id": "", "content": "hi"}},
			},
			wantErr: true,
		},
		{
			name: "bad on_existing_system rejected",
			settings: map[string]any{
				"inject_templates": []any{
					map[string]any{"id": "t1", "content": "hi", "on_existing_system": "append"},
				},
			},
			wantErr: true,
		},
		{
			name: "non-system position rejected",
			settings: map[string]any{
				"inject_templates": []any{
					map[string]any{"id": "t1", "content": "hi", "position": "user"},
				},
			},
			wantErr: true,
		},
		{
			name:     "bad placeholder syntax rejected",
			settings: injectOnly("hello {{ bad name! }}"),
			wantErr:  true,
		},
		{
			name: "duplicate named template name rejected",
			settings: map[string]any{
				"named_templates": []any{
					map[string]any{"name": "a", "versions": []any{map[string]any{"version": "v1", "content": "x"}}},
					map[string]any{"name": "a", "versions": []any{map[string]any{"version": "v1", "content": "x"}}},
				},
			},
			wantErr: true,
		},
		{
			name: "duplicate version rejected",
			settings: map[string]any{
				"named_templates": []any{
					map[string]any{"name": "a", "versions": []any{
						map[string]any{"version": "v1", "content": "x"},
						map[string]any{"version": "v1", "content": "y"},
					}},
				},
			},
			wantErr: true,
		},
		{
			name: "duplicate label rejected",
			settings: map[string]any{
				"named_templates": []any{
					map[string]any{"name": "a", "versions": []any{
						map[string]any{"version": "v1", "labels": []any{"stable"}, "content": "x"},
						map[string]any{"version": "v2", "labels": []any{"stable"}, "content": "y"},
					}},
				},
			},
			wantErr: true,
		},
		{
			name: "unresolved default_label rejected",
			settings: map[string]any{
				"named_templates": []any{
					map[string]any{"name": "a", "versions": []any{
						map[string]any{"version": "v1", "labels": []any{"stable"}, "content": "x"},
					}},
				},
				"default_label": "canary",
			},
			wantErr: true,
		},
		{
			name: "bad required_variables type rejected",
			settings: map[string]any{
				"named_templates": []any{
					map[string]any{"name": "a", "versions": []any{
						map[string]any{"version": "v1", "content": "{{p}}", "required_variables": map[string]any{
							"p": map[string]any{"type": "date"},
						}},
					}},
				},
			},
			wantErr: true,
		},
		{
			name: "negative max_length rejected",
			settings: map[string]any{
				"named_templates": []any{
					map[string]any{"name": "a", "versions": []any{
						map[string]any{"version": "v1", "content": "{{p}}", "required_variables": map[string]any{
							"p": map[string]any{"type": "string", "max_length": -1},
						}},
					}},
				},
			},
			wantErr: true,
		},
		{
			name: "blank enum entry rejected",
			settings: map[string]any{
				"named_templates": []any{
					map[string]any{"name": "a", "versions": []any{
						map[string]any{"version": "v1", "content": "{{p}}", "required_variables": map[string]any{
							"p": map[string]any{"type": "string", "enum": []any{"a", "  "}},
						}},
					}},
				},
			},
			wantErr: true,
		},
		{
			name: "valid json array content accepted",
			settings: map[string]any{
				"named_templates": []any{
					map[string]any{"name": "a", "versions": []any{
						map[string]any{"version": "v1", "labels": []any{"stable"}, "content": `[{"role":"system","content":"hi {{p}}"}]`, "required_variables": map[string]any{
							"p": map[string]any{"type": "string"},
						}},
					}},
				},
				"default_label": "stable",
			},
		},
		{
			name: "malformed json array content rejected",
			settings: map[string]any{
				"named_templates": []any{
					map[string]any{"name": "a", "versions": []any{
						map[string]any{"version": "v1", "content": `[{"role":"system"`},
					}},
				},
			},
			wantErr: true,
		},
		{
			name: "non-object json array element rejected",
			settings: map[string]any{
				"named_templates": []any{
					map[string]any{"name": "a", "versions": []any{
						map[string]any{"version": "v1", "content": `["not an object"]`},
					}},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConfig(tt.settings)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestConfigApplyDefaults(t *testing.T) {
	cfg, err := parseConfig(injectOnly("hi"))
	require.NoError(t, err)
	assert.Equal(t, engineMustache, cfg.TemplateEngine)
	assert.Equal(t, onMissingContextError, cfg.OnMissingContextVariable)
	assert.Equal(t, onMissingClientError, cfg.OnMissingClientVariable)
	require.Len(t, cfg.InjectTemplates, 1)
	assert.Equal(t, "system", cfg.InjectTemplates[0].Position)
	assert.Equal(t, "system", cfg.InjectTemplates[0].Role)
	assert.Equal(t, onExistingMerge, cfg.InjectTemplates[0].OnExistingSystem)
	require.NotNil(t, cfg.EscapeJSONControlChars)
	assert.True(t, *cfg.EscapeJSONControlChars)
}

func TestConfigEscapeControlCharsExplicitFalse(t *testing.T) {
	settings := injectOnly("hi")
	settings["escape_json_control_chars"] = false
	cfg, err := parseConfig(settings)
	require.NoError(t, err)
	require.NotNil(t, cfg.EscapeJSONControlChars)
	assert.False(t, *cfg.EscapeJSONControlChars)
}
