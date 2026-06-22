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

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const (
	actionAllow  = "allow"
	actionReject = "reject"
)

type evalContext struct {
	allowed    map[string]struct{}
	toolByName map[string]adapter.CanonicalTool
	rules      []RuleConfig
}

type engineOutcome struct {
	matched   bool
	rejection *appplugins.PluginError
	extras    ToolCallValidationData
}

var validatorRegistry = map[string]Validator{
	validatorNotInAllowedList: notInAllowedListValidator{},
	validatorJSONSchema:       jsonSchemaValidator{},
}

func validatorFor(name string) (Validator, bool) {
	v, ok := validatorRegistry[name]
	return v, ok
}

func buildEvalContext(cfg *Config, creq *adapter.CanonicalRequest) *evalContext {
	allowed := make(map[string]struct{}, len(creq.Tools))
	toolByName := make(map[string]adapter.CanonicalTool, len(creq.Tools))
	for _, t := range creq.Tools {
		allowed[t.Name] = struct{}{}
		toolByName[t.Name] = t
	}
	return &evalContext{allowed: allowed, toolByName: toolByName, rules: cfg.Rules}
}

func ruleApplies(rule RuleConfig, tc adapter.CanonicalToolCall) bool {
	if rule.Validator == validatorNotInAllowedList {
		return true
	}
	if rule.Tool == "" || rule.Tool == "*" {
		return true
	}
	return rule.Tool == tc.Name
}

func runRules(ctx context.Context, eval *evalContext, mode policy.Mode, toolCalls []adapter.CanonicalToolCall) engineOutcome {
	for _, tc := range toolCalls {
		for _, rule := range eval.rules {
			if !ruleApplies(rule, tc) {
				continue
			}
			v, ok := validatorFor(rule.Validator)
			if !ok {
				continue
			}
			res, err := v.Evaluate(validatorInput{ctx: ctx, toolCall: tc, rule: rule, eval: eval})
			if err != nil || !res.matched {
				continue
			}
			outcome := engineOutcome{
				matched: true,
				extras: ToolCallValidationData{
					Validator:         rule.Validator,
					Action:            actionReject,
					ToolName:          tc.Name,
					SemanticReasoning: res.reasoning,
				},
			}
			if mode != policy.ModeObserve {
				outcome.rejection = newPluginError(res)
			}
			return outcome
		}
	}
	return engineOutcome{}
}
