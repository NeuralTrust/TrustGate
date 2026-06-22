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
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func TestRuleApplies(t *testing.T) {
	t.Parallel()

	tc := adapter.CanonicalToolCall{Name: "send_email"}
	cases := []struct {
		name string
		rule RuleConfig
		want bool
	}{
		{"not_in_allowed_list applies to any tool", RuleConfig{Validator: validatorNotInAllowedList, Tool: "other"}, true},
		{"empty tool applies to all", RuleConfig{Validator: validatorJSONSchema, Tool: ""}, true},
		{"wildcard tool applies to all", RuleConfig{Validator: validatorJSONSchema, Tool: "*"}, true},
		{"named tool matches", RuleConfig{Validator: validatorJSONSchema, Tool: "send_email"}, true},
		{"named tool does not match other", RuleConfig{Validator: validatorJSONSchema, Tool: "run_shell"}, false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := ruleApplies(c.rule, tc); got != c.want {
				t.Fatalf("ruleApplies = %v, want %v", got, c.want)
			}
		})
	}
}

func rejectingEval() *evalContext {
	return &evalContext{
		allowed:    map[string]struct{}{"other": {}},
		toolByName: map[string]adapter.CanonicalTool{"send_email": {Name: "send_email", Schema: emailSchema()}},
	}
}

func TestRunRulesDeclaredOrderFirstRejectWins(t *testing.T) {
	t.Parallel()

	toolCalls := []adapter.CanonicalToolCall{{Name: "send_email", Arguments: `{"subject":"hi"}`}}

	t.Run("json_schema first", func(t *testing.T) {
		t.Parallel()
		eval := rejectingEval()
		eval.rules = []RuleConfig{
			{Validator: validatorJSONSchema, Tool: "*"},
			{Validator: validatorNotInAllowedList},
		}
		out := runRules(context.Background(), eval, policy.ModeEnforce, toolCalls)
		if !out.matched || out.rejection == nil {
			t.Fatalf("expected rejection, got %+v", out)
		}
		if out.rejection.Type != typeToolSchemaInvalid {
			t.Fatalf("type = %q, want %q", out.rejection.Type, typeToolSchemaInvalid)
		}
	})

	t.Run("not_in_allowed_list first", func(t *testing.T) {
		t.Parallel()
		eval := rejectingEval()
		eval.rules = []RuleConfig{
			{Validator: validatorNotInAllowedList},
			{Validator: validatorJSONSchema, Tool: "*"},
		}
		out := runRules(context.Background(), eval, policy.ModeEnforce, toolCalls)
		if !out.matched || out.rejection == nil {
			t.Fatalf("expected rejection, got %+v", out)
		}
		if out.rejection.Type != typeToolNotInList {
			t.Fatalf("type = %q, want %q", out.rejection.Type, typeToolNotInList)
		}
	})
}

func TestRunRulesNamedToolMatching(t *testing.T) {
	t.Parallel()

	toolCalls := []adapter.CanonicalToolCall{{Name: "send_email", Arguments: `{"subject":"hi"}`}}

	t.Run("named rule for other tool does not fire", func(t *testing.T) {
		t.Parallel()
		eval := rejectingEval()
		eval.rules = []RuleConfig{{Validator: validatorJSONSchema, Tool: "run_shell"}}
		out := runRules(context.Background(), eval, policy.ModeEnforce, toolCalls)
		if out.matched {
			t.Fatalf("expected no match, got %+v", out)
		}
	})

	t.Run("wildcard rule fires", func(t *testing.T) {
		t.Parallel()
		eval := rejectingEval()
		eval.rules = []RuleConfig{{Validator: validatorJSONSchema, Tool: "*"}}
		out := runRules(context.Background(), eval, policy.ModeEnforce, toolCalls)
		if !out.matched || out.rejection == nil {
			t.Fatalf("expected rejection, got %+v", out)
		}
	})
}

func TestRunRulesObserveModeDoesNotReject(t *testing.T) {
	t.Parallel()

	toolCalls := []adapter.CanonicalToolCall{{Name: "send_email", Arguments: `{"subject":"hi"}`}}
	eval := rejectingEval()
	eval.rules = []RuleConfig{{Validator: validatorJSONSchema, Tool: "*"}}

	out := runRules(context.Background(), eval, policy.ModeObserve, toolCalls)
	if !out.matched {
		t.Fatalf("expected matched outcome in observe mode")
	}
	if out.rejection != nil {
		t.Fatalf("observe mode must not reject, got %+v", out.rejection)
	}
	if out.extras.Action != actionReject {
		t.Fatalf("extras action = %q, want %q", out.extras.Action, actionReject)
	}
	if out.extras.ToolName != "send_email" {
		t.Fatalf("extras tool name = %q, want send_email", out.extras.ToolName)
	}
}

func TestRunRulesUnimplementedValidatorFailsOpen(t *testing.T) {
	t.Parallel()

	eval := rejectingEval()
	eval.rules = []RuleConfig{{Validator: validatorRegex, Tool: "*", ArgumentPath: "$.to", Pattern: ".*"}}
	out := runRules(context.Background(), eval, policy.ModeEnforce,
		[]adapter.CanonicalToolCall{{Name: "send_email", Arguments: `{"to":"x"}`}})
	if out.matched {
		t.Fatalf("unimplemented validator must fail open, got %+v", out)
	}
}
