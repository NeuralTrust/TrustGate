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

package promptdecorator

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func decoratorSettings(fields map[string]any) map[string]any {
	decorator := map[string]any{
		"position": "end",
		"role":     "user",
		"content":  "content",
	}
	for key, value := range fields {
		decorator[key] = value
	}
	return map[string]any{"decorators": []any{decorator}}
}

func TestConfigAcceptsValidPositionRoleStrategyAndScopeCombinations(t *testing.T) {
	scopes := []string{"", "consumer", "global"}
	positions := []string{"start", "end", "after_system", "before_last_user"}
	roles := []string{"user", "assistant"}
	strategies := []string{"merge", "replace", "append", "skip"}

	for _, scope := range scopes {
		for _, position := range positions {
			for _, role := range roles {
				t.Run(fmt.Sprintf("%s/%s/%s", scope, position, role), func(t *testing.T) {
					settings := decoratorSettings(map[string]any{"position": position, "role": role})
					settings["scope"] = scope

					cfg, err := parseConfig(settings)

					require.NoError(t, err)
					require.Equal(t, scope, cfg.Scope)
					require.Equal(t, position, string(cfg.Decorators[0].Position))
					require.Equal(t, role, string(cfg.Decorators[0].Role))
					require.Nil(t, cfg.Decorators[0].OnExistingSystem)
				})
			}
		}
		for _, strategy := range strategies {
			t.Run(fmt.Sprintf("%s/system/%s", scope, strategy), func(t *testing.T) {
				settings := decoratorSettings(map[string]any{
					"position":           "system",
					"role":               "system",
					"on_existing_system": strategy,
				})
				settings["scope"] = scope

				cfg, err := parseConfig(settings)

				require.NoError(t, err)
				require.NotNil(t, cfg.Decorators[0].OnExistingSystem)
				require.Equal(t, strategy, string(*cfg.Decorators[0].OnExistingSystem))
			})
		}
	}
}

func TestConfigAcceptsOptionalFieldOmissions(t *testing.T) {
	tests := map[string]map[string]any{
		"scope omitted":                decoratorSettings(nil),
		"decorators omitted":           {"require_system_message": true},
		"require and strategy omitted": decoratorSettings(nil),
	}
	for name, settings := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := parseConfig(settings)
			require.NoError(t, err)
		})
	}
}

func TestConfigDoesNotImposeDecoratorCountOrContentSizeCaps(t *testing.T) {
	decorators := make([]any, 1001)
	for i := range decorators {
		decorators[i] = decoratorSettings(nil)["decorators"].([]any)[0]
	}
	decorators[0].(map[string]any)["content"] = strings.Repeat("x", 1<<20)

	cfg, err := parseConfig(map[string]any{"decorators": decorators})

	require.NoError(t, err)
	require.Len(t, cfg.Decorators, 1001)
	require.Len(t, cfg.Decorators[0].Content, 1<<20)
}

func TestConfigRejectsInvalidValuesAndPairings(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		wantErr  string
	}{
		{"unknown scope", map[string]any{"scope": "tenant", "require_system_message": true}, `prompt_decorator: scope "tenant" must be consumer or global`},
		{"whitespace scope", map[string]any{"scope": " ", "require_system_message": true}, `prompt_decorator: scope " " must be consumer or global`},
		{"blank position", decoratorSettings(map[string]any{"position": " "}), "prompt_decorator: decorators[0].position must not be blank"},
		{"unknown position", decoratorSettings(map[string]any{"position": "middle"}), `prompt_decorator: decorators[0].position "middle" must be start, end, after_system, before_last_user, or system`},
		{"blank role", decoratorSettings(map[string]any{"role": " "}), "prompt_decorator: decorators[0].role must not be blank"},
		{"unknown role", decoratorSettings(map[string]any{"role": "tool"}), `prompt_decorator: decorators[0].role "tool" must be system, user, or assistant`},
		{"blank content", decoratorSettings(map[string]any{"content": " \t\n"}), "prompt_decorator: decorators[0].content must not be blank"},
		{"system role at non-system position", decoratorSettings(map[string]any{"role": "system"}), "prompt_decorator: decorators[0].role system requires position system"},
		{
			"system position with user role",
			decoratorSettings(map[string]any{"position": "system", "on_existing_system": "merge"}),
			"prompt_decorator: decorators[0].position system requires role system",
		},
		{
			"system position with assistant role",
			decoratorSettings(map[string]any{"position": "system", "role": "assistant", "on_existing_system": "merge"}),
			"prompt_decorator: decorators[0].position system requires role system",
		},
		{
			"system position without strategy",
			decoratorSettings(map[string]any{"position": "system", "role": "system"}),
			"prompt_decorator: decorators[0].on_existing_system is required with position system",
		},
		{
			"system position with blank strategy",
			decoratorSettings(map[string]any{"position": "system", "role": "system", "on_existing_system": ""}),
			`prompt_decorator: decorators[0].on_existing_system "" must be merge, replace, append, or skip`,
		},
		{
			"system position with unknown strategy",
			decoratorSettings(map[string]any{"position": "system", "role": "system", "on_existing_system": "prepend"}),
			`prompt_decorator: decorators[0].on_existing_system "prepend" must be merge, replace, append, or skip`,
		},
		{
			"non-system position with blank strategy",
			decoratorSettings(map[string]any{"on_existing_system": ""}),
			"prompt_decorator: decorators[0].on_existing_system is only allowed with position system",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConfig(tt.settings)
			require.EqualError(t, err, tt.wantErr)
		})
	}
}

func TestConfigRejectsSettingsWithoutUsefulAction(t *testing.T) {
	for name, settings := range map[string]map[string]any{
		"empty settings":             {},
		"empty decorators":           {"decorators": []any{}},
		"explicit false requirement": {"require_system_message": false},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseConfig(settings)
			require.EqualError(t, err, "prompt_decorator: at least one decorator or require_system_message=true is required")
		})
	}
}

func TestConfigRejectsUnknownFields(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		field    string
	}{
		{"top-level", map[string]any{"require_system_message": true, "mode": "enforce"}, "mode"},
		{"decorator", decoratorSettings(map[string]any{"priority": 1}), "priority"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConfig(tt.settings)
			require.Error(t, err)
			require.Contains(t, err.Error(), "prompt_decorator: invalid settings")
			require.Contains(t, err.Error(), tt.field)
		})
	}
}

func TestConfigRejectsMalformedTypes(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		field    string
	}{
		{"null scope", map[string]any{"scope": nil, "require_system_message": true}, "scope"},
		{"null decorators", map[string]any{"decorators": nil, "require_system_message": true}, "decorators"},
		{"null require system", map[string]any{"require_system_message": nil}, "require_system_message"},
		{"null decorator entry", map[string]any{"decorators": []any{nil}}, "decorators[0]"},
		{"null position", decoratorSettings(map[string]any{"position": nil}), "decorators[0].position"},
		{"null role", decoratorSettings(map[string]any{"role": nil}), "decorators[0].role"},
		{"null content", decoratorSettings(map[string]any{"content": nil}), "decorators[0].content"},
		{"null strategy", decoratorSettings(map[string]any{"on_existing_system": nil}), "decorators[0].on_existing_system"},
		{"scope", map[string]any{"scope": true, "require_system_message": true}, "scope"},
		{"decorators", map[string]any{"decorators": map[string]any{}}, "decorators"},
		{"require system", map[string]any{"require_system_message": "true"}, "require_system_message"},
		{"decorator entry", map[string]any{"decorators": []any{"invalid"}}, "decorators[0]"},
		{"position", decoratorSettings(map[string]any{"position": 1}), "position"},
		{"role", decoratorSettings(map[string]any{"role": false}), "role"},
		{"content", decoratorSettings(map[string]any{"content": 12}), "content"},
		{
			"strategy",
			decoratorSettings(map[string]any{"position": "system", "role": "system", "on_existing_system": true}),
			"on_existing_system",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConfig(tt.settings)
			require.Error(t, err)
			require.Contains(t, err.Error(), "prompt_decorator: invalid settings")
			require.Contains(t, err.Error(), tt.field)
			if strings.HasPrefix(tt.name, "null") {
				require.Contains(t, err.Error(), "received null")
			}
		})
	}
}
