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

package tool_call_validation

import (
	"net/http"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func validFullSettings() map[string]any {
	return map[string]any{
		"scope": "consumer",
		"semantic": map[string]any{
			"provider": "openai",
			"api_key":  "sk-test",
			"model":    "gpt-4o-mini",
		},
		"rules": []any{
			map[string]any{
				"validator": "not_in_allowed_list",
				"behavior":  "reject_response",
			},
			map[string]any{
				"tool":          "send_email",
				"validator":     "regex",
				"argument_path": "$.to",
				"pattern":       `.*@evil\.com$`,
				"behavior":      "reject_response",
			},
			map[string]any{
				"tool":          "run_shell",
				"validator":     "denylist",
				"argument_path": "$.code",
				"denylist":      []any{"rm -rf", "curl"},
				"behavior":      "replace_with",
				"redact_with":   "[blocked]",
			},
		},
	}
}

func TestParseConfigMatrix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		settings  map[string]any
		expectErr bool
	}{
		{
			name:      "valid full config from the issue",
			settings:  validFullSettings(),
			expectErr: false,
		},
		{
			name: "scope present is accepted and ignored",
			settings: map[string]any{
				"scope": "consumer",
				"rules": []any{
					map[string]any{"validator": "json_schema", "behavior": "reject_response"},
				},
			},
			expectErr: false,
		},
		{
			name: "no rules is rejected",
			settings: map[string]any{
				"rules": []any{},
			},
			expectErr: true,
		},
		{
			name: "unknown validator is rejected",
			settings: map[string]any{
				"rules": []any{
					map[string]any{"validator": "made_up", "behavior": "reject_response"},
				},
			},
			expectErr: true,
		},
		{
			name: "unknown behavior is rejected",
			settings: map[string]any{
				"rules": []any{
					map[string]any{"validator": "json_schema", "behavior": "explode"},
				},
			},
			expectErr: true,
		},
		{
			name: "redaction behavior on a tool-level validator is rejected",
			settings: map[string]any{
				"rules": []any{
					map[string]any{"validator": "not_in_allowed_list", "behavior": "redact"},
				},
			},
			expectErr: true,
		},
		{
			name: "regex without pattern is rejected",
			settings: map[string]any{
				"rules": []any{
					map[string]any{"validator": "regex", "argument_path": "$.to", "behavior": "reject_response"},
				},
			},
			expectErr: true,
		},
		{
			name: "regex without argument_path is rejected",
			settings: map[string]any{
				"rules": []any{
					map[string]any{"validator": "regex", "pattern": ".*", "behavior": "reject_response"},
				},
			},
			expectErr: true,
		},
		{
			name: "regex with an uncompilable pattern is rejected",
			settings: map[string]any{
				"rules": []any{
					map[string]any{"validator": "regex", "argument_path": "$.to", "pattern": "([a-z", "behavior": "reject_response"},
				},
			},
			expectErr: true,
		},
		{
			name: "denylist without denylist values is rejected",
			settings: map[string]any{
				"rules": []any{
					map[string]any{"validator": "denylist", "argument_path": "$.code", "behavior": "reject_response"},
				},
			},
			expectErr: true,
		},
		{
			name: "denylist without argument_path is rejected",
			settings: map[string]any{
				"rules": []any{
					map[string]any{"validator": "denylist", "denylist": []any{"rm -rf"}, "behavior": "reject_response"},
				},
			},
			expectErr: true,
		},
		{
			name: "tool-level validator with argument_path is rejected",
			settings: map[string]any{
				"rules": []any{
					map[string]any{"validator": "json_schema", "argument_path": "$.x", "behavior": "reject_response"},
				},
			},
			expectErr: true,
		},
		{
			name: "replace_with without redact_with is rejected",
			settings: map[string]any{
				"rules": []any{
					map[string]any{"validator": "denylist", "argument_path": "$.code", "denylist": []any{"rm -rf"}, "behavior": "replace_with"},
				},
			},
			expectErr: true,
		},
		{
			name: "semantic rule without semantic block is rejected",
			settings: map[string]any{
				"rules": []any{
					map[string]any{"validator": "semantic", "behavior": "reject_response"},
				},
			},
			expectErr: true,
		},
		{
			name: "semantic provider other than openai is rejected",
			settings: map[string]any{
				"semantic": map[string]any{"provider": "anthropic", "api_key": "sk-test"},
				"rules": []any{
					map[string]any{"validator": "semantic", "behavior": "reject_response"},
				},
			},
			expectErr: true,
		},
		{
			name: "semantic openai without api_key is rejected",
			settings: map[string]any{
				"semantic": map[string]any{"provider": "openai"},
				"rules": []any{
					map[string]any{"validator": "semantic", "behavior": "reject_response"},
				},
			},
			expectErr: true,
		},
		{
			name: "argument_path that is not a JSONPath is rejected",
			settings: map[string]any{
				"rules": []any{
					map[string]any{"validator": "regex", "argument_path": "to", "pattern": ".*", "behavior": "reject_response"},
				},
			},
			expectErr: true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := parseConfig(tc.settings)
			if tc.expectErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.expectErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestParseConfigAppliesDefaults(t *testing.T) {
	t.Parallel()

	settings := map[string]any{
		"semantic": map[string]any{"provider": "openai", "api_key": "sk-test"},
		"rules": []any{
			map[string]any{"validator": "json_schema"},
			map[string]any{"validator": "denylist", "argument_path": "$.code", "denylist": []any{"rm -rf"}, "behavior": "redact"},
		},
	}

	cfg, err := parseConfig(settings)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg.Rules[0].Behavior != behaviorReject {
		t.Fatalf("expected default behavior %q, got %q", behaviorReject, cfg.Rules[0].Behavior)
	}
	if cfg.Rules[1].RedactWith != defaultRedactionMarker {
		t.Fatalf("expected default redact_with %q, got %q", defaultRedactionMarker, cfg.Rules[1].RedactWith)
	}
	if cfg.Semantic.Model != defaultSemanticModel {
		t.Fatalf("expected default semantic model %q, got %q", defaultSemanticModel, cfg.Semantic.Model)
	}
}

func TestParseConfigEmptyProviderStaysDisabled(t *testing.T) {
	t.Parallel()

	settings := map[string]any{
		"semantic": map[string]any{"api_key": "sk-test"},
		"rules": []any{
			map[string]any{"validator": "semantic", "behavior": "reject_response"},
		},
	}

	cfg, err := parseConfig(settings)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg.Semantic.Provider != "" {
		t.Fatalf("expected provider to stay empty (disabled), got %q", cfg.Semantic.Provider)
	}
	if cfg.Semantic.Model != "" {
		t.Fatalf("expected model to stay empty when provider is disabled, got %q", cfg.Semantic.Model)
	}
}

func TestValidateConfigScopeIgnored(t *testing.T) {
	t.Parallel()

	p := New(nil, nil, nil)
	if err := p.ValidateConfig(validFullSettings()); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestScaffoldingValueTypes(t *testing.T) {
	t.Parallel()

	in := validatorInput{
		toolCall: adapter.CanonicalToolCall{Name: "send_email", Arguments: `{"to":"a@b.com"}`},
		rule:     RuleConfig{Validator: validatorRegex, ArgumentPath: "$.to"},
	}
	if in.toolCall.Name != "send_email" {
		t.Fatalf("unexpected tool call name %q", in.toolCall.Name)
	}
	if in.rule.Validator != validatorRegex {
		t.Fatalf("unexpected rule validator %q", in.rule.Validator)
	}

	v := violation{
		matched:      true,
		rejectType:   "tool_call_validation_failed",
		status:       http.StatusBadGateway,
		message:      "blocked",
		reasoning:    "policy",
		matchedValue: "a@b.com",
	}
	if !v.matched || v.status != http.StatusBadGateway || v.rejectType == "" ||
		v.message == "" || v.reasoning == "" || v.matchedValue == "" {
		t.Fatalf("unexpected violation: %+v", v)
	}

	setExtras(nil, ToolCallValidationData{Validator: validatorRegex, Action: behaviorReject})
}
