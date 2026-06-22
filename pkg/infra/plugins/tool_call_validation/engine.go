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
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const (
	actionAllow  = "allow"
	actionReject = "reject"
	actionRedact = "redact"
)

type evalContext struct {
	allowed    map[string]struct{}
	toolByName map[string]adapter.CanonicalTool
	rules      []RuleConfig
	semantic   *SemanticConfig
	llm        providers.Client
	userPrompt string
	reasoning  string
}

type engineOutcome struct {
	matched    bool
	rejection  *appplugins.PluginError
	redacted   bool
	redactions []redaction
	extras     ToolCallValidationData
}

var validatorRegistry = map[string]Validator{
	validatorNotInAllowedList: notInAllowedListValidator{},
	validatorJSONSchema:       jsonSchemaValidator{},
	validatorSemantic:         semanticValidator{},
	validatorRegex:            regexValidator{},
	validatorDenylist:         denylistValidator{},
}

func validatorFor(name string) (Validator, bool) {
	v, ok := validatorRegistry[name]
	return v, ok
}

func buildEvalContext(cfg *Config, creq *adapter.CanonicalRequest, cresp *adapter.CanonicalResponse, llm providers.Client) *evalContext {
	allowed := make(map[string]struct{}, len(creq.Tools))
	toolByName := make(map[string]adapter.CanonicalTool, len(creq.Tools))
	for _, t := range creq.Tools {
		allowed[t.Name] = struct{}{}
		toolByName[t.Name] = t
	}
	return &evalContext{
		allowed:    allowed,
		toolByName: toolByName,
		rules:      cfg.Rules,
		semantic:   cfg.Semantic,
		llm:        llm,
		userPrompt: lastUserPrompt(creq),
		reasoning:  reasoningSummary(cresp),
	}
}

func lastUserPrompt(creq *adapter.CanonicalRequest) string {
	for i := len(creq.Messages) - 1; i >= 0; i-- {
		msg := creq.Messages[i]
		if msg.Role == "user" && msg.Content != "" {
			return msg.Content
		}
	}
	return ""
}

func reasoningSummary(cresp *adapter.CanonicalResponse) string {
	if cresp == nil || cresp.Reasoning == nil {
		return ""
	}
	if cresp.Reasoning.Summary != nil && *cresp.Reasoning.Summary != "" {
		return *cresp.Reasoning.Summary
	}
	return cresp.Reasoning.ThinkingText
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
	var redactions []redaction
	var redactExtras ToolCallValidationData
	redacted := false
	for idx, tc := range toolCalls {
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
			if isRedactionBehavior(rule.Behavior) {
				if !redacted {
					redactExtras = redactionExtras(rule, tc)
					redacted = true
				}
				if mode != policy.ModeObserve {
					redactions = append(redactions, buildRedaction(idx, rule))
				}
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
				outcome.rejection = rejectionForRule(rule, res, tc.Name)
			}
			return outcome
		}
	}
	if redacted {
		if mode == policy.ModeObserve {
			return engineOutcome{matched: true, extras: redactExtras}
		}
		return engineOutcome{matched: true, redacted: true, redactions: redactions, extras: redactExtras}
	}
	return engineOutcome{}
}

func redactionExtras(rule RuleConfig, tc adapter.CanonicalToolCall) ToolCallValidationData {
	return ToolCallValidationData{
		Validator: rule.Validator,
		Action:    actionRedact,
		ToolName:  tc.Name,
	}
}

func buildRedaction(callIndex int, rule RuleConfig) redaction {
	r := redaction{
		callIndex:   callIndex,
		path:        rule.ArgumentPath,
		replaceWith: rule.RedactWith,
	}
	if rule.Validator == validatorDenylist && rule.Behavior != behaviorReplaceWith {
		r.terms = rule.Denylist
		return r
	}
	r.whole = true
	return r
}
