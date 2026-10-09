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
	"reflect"
	"strings"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

const (
	policyTopic                = "topic_policy"
	policyContent              = "content_policy"
	policyWord                 = "word_policy"
	policySensitiveInformation = "sensitive_information"
	policyContextualGrounding  = "contextual_grounding"
)

const (
	matchTypeCustomWord = "custom"
	matchTypeRegex      = "regex"
)

type finding struct {
	policy    string
	name      string
	matchType string
	action    string
}

type assessmentResult struct {
	intervened bool
	// partialCoverage is the guardrail reporting that it guarded fewer of the
	// text's characters than the text has: the rest was never judged.
	partialCoverage bool
	block           *finding
	anonymize       *finding
}

func buildApplyInput(cfg Settings, text string, source types.GuardrailContentSource) *bedrockruntime.ApplyGuardrailInput {
	return &bedrockruntime.ApplyGuardrailInput{
		GuardrailIdentifier: aws.String(cfg.GuardrailID),
		GuardrailVersion:    aws.String(cfg.Version),
		Source:              source,
		Content: []types.GuardrailContentBlock{
			&types.GuardrailContentBlockMemberText{
				Value: types.GuardrailTextBlock{
					Text: aws.String(text),
				},
			},
		},
	}
}

func inspect(output *bedrockruntime.ApplyGuardrailOutput, piiAction string) assessmentResult {
	var res assessmentResult
	if output == nil {
		return res
	}
	res.intervened = output.Action == types.GuardrailActionGuardrailIntervened
	res.partialCoverage = partiallyCovered(output.GuardrailCoverage)
	for i := range output.Assessments {
		inspectTopic(output.Assessments[i].TopicPolicy, &res)
	}
	for i := range output.Assessments {
		inspectContent(output.Assessments[i].ContentPolicy, &res)
	}
	for i := range output.Assessments {
		inspectWord(output.Assessments[i].WordPolicy, &res)
	}
	for i := range output.Assessments {
		inspectSensitive(output.Assessments[i].SensitiveInformationPolicy, piiAction, &res)
	}
	for i := range output.Assessments {
		inspectContextualGrounding(output.Assessments[i].ContextualGroundingPolicy, &res)
	}
	return res
}

// readPolicies are the GuardrailAssessment members inspect reads. Any other
// *Policy member is one AWS can intervene on without this plugin seeing why.
var readPolicies = map[string]bool{
	"TopicPolicy":                true,
	"ContentPolicy":              true,
	"WordPolicy":                 true,
	"SensitiveInformationPolicy": true,
	"ContextualGroundingPolicy":  true,
}

// unparsedPolicies names, in snake_case and comma-separated, every policy
// assessment present in assessments that inspect does not read — the
// failure_detail of a verdict_incomplete. It walks GuardrailAssessment by
// reflection rather than naming AutomatedReasoningPolicy, so a policy type a
// future SDK bump adds is named without anyone updating a list. Only called
// on the verdict_incomplete path, never on a clean or explained verdict.
func unparsedPolicies(assessments []types.GuardrailAssessment) string {
	var names []string
	seen := map[string]bool{}
	for i := range assessments {
		v := reflect.ValueOf(assessments[i])
		t := v.Type()
		for j := 0; j < t.NumField(); j++ {
			f := t.Field(j)
			if !f.IsExported() || !strings.HasSuffix(f.Name, "Policy") || readPolicies[f.Name] {
				continue
			}
			fv := v.Field(j)
			if fv.Kind() != reflect.Pointer || fv.IsNil() || seen[f.Name] {
				continue
			}
			seen[f.Name] = true
			names = append(names, snakeCase(f.Name))
		}
	}
	return strings.Join(names, ",")
}

func snakeCase(s string) string {
	var b strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) {
			if i > 0 {
				b.WriteByte('_')
			}
			r = unicode.ToLower(r)
		}
		b.WriteRune(r)
	}
	return b.String()
}

func inspectTopic(p *types.GuardrailTopicPolicyAssessment, res *assessmentResult) {
	if p == nil || res.block != nil {
		return
	}
	for i := range p.Topics {
		t := p.Topics[i]
		if t.Action == types.GuardrailTopicPolicyActionBlocked {
			res.block = &finding{
				policy:    policyTopic,
				name:      aws.ToString(t.Name),
				matchType: string(t.Type),
				action:    string(t.Action),
			}
			return
		}
	}
}

func inspectContent(p *types.GuardrailContentPolicyAssessment, res *assessmentResult) {
	if p == nil || res.block != nil {
		return
	}
	for i := range p.Filters {
		f := p.Filters[i]
		if f.Action == types.GuardrailContentPolicyActionBlocked {
			res.block = &finding{
				policy:    policyContent,
				name:      string(f.Type),
				matchType: string(f.Type),
				action:    string(f.Action),
			}
			return
		}
	}
}

func inspectWord(p *types.GuardrailWordPolicyAssessment, res *assessmentResult) {
	if p == nil || res.block != nil {
		return
	}
	for i := range p.CustomWords {
		w := p.CustomWords[i]
		if w.Action == types.GuardrailWordPolicyActionBlocked {
			res.block = &finding{
				policy:    policyWord,
				matchType: matchTypeCustomWord,
				action:    string(w.Action),
			}
			return
		}
	}
	for i := range p.ManagedWordLists {
		w := p.ManagedWordLists[i]
		if w.Action == types.GuardrailWordPolicyActionBlocked {
			res.block = &finding{
				policy:    policyWord,
				name:      string(w.Type),
				matchType: string(w.Type),
				action:    string(w.Action),
			}
			return
		}
	}
}

func inspectSensitive(p *types.GuardrailSensitiveInformationPolicyAssessment, piiAction string, res *assessmentResult) {
	if p == nil {
		return
	}
	for i := range p.PiiEntities {
		e := p.PiiEntities[i]
		classifyPII(e.Action, string(e.Type), string(e.Type), piiAction, res)
	}
	for i := range p.Regexes {
		r := p.Regexes[i]
		classifyPII(r.Action, aws.ToString(r.Name), matchTypeRegex, piiAction, res)
	}
}

func classifyPII(action types.GuardrailSensitiveInformationPolicyAction, name, matchType, piiAction string, res *assessmentResult) {
	switch action {
	case types.GuardrailSensitiveInformationPolicyActionBlocked:
		if res.block == nil {
			res.block = newSensitiveFinding(name, matchType, action)
		}
	case types.GuardrailSensitiveInformationPolicyActionAnonymized:
		if piiAction == piiActionAnonymize {
			if res.anonymize == nil {
				res.anonymize = newSensitiveFinding(name, matchType, action)
			}
			return
		}
		if res.block == nil {
			res.block = newSensitiveFinding(name, matchType, action)
		}
	}
}

func newSensitiveFinding(name, matchType string, action types.GuardrailSensitiveInformationPolicyAction) *finding {
	return &finding{
		policy:    policySensitiveInformation,
		name:      name,
		matchType: matchType,
		action:    string(action),
	}
}

func inspectContextualGrounding(p *types.GuardrailContextualGroundingPolicyAssessment, res *assessmentResult) {
	if p == nil || res.block != nil {
		return
	}
	for i := range p.Filters {
		f := p.Filters[i]
		if f.Action == types.GuardrailContextualGroundingPolicyActionBlocked {
			res.block = &finding{
				policy:    policyContextualGrounding,
				matchType: string(f.Type),
				action:    string(f.Action),
			}
			return
		}
	}
}

// partiallyCovered reports whether ApplyGuardrail guarded fewer text characters
// than it was sent. An answer that reports no coverage is not partial: the
// field is absent on answers that predate it.
func partiallyCovered(coverage *types.GuardrailCoverage) bool {
	if coverage == nil || coverage.TextCharacters == nil {
		return false
	}
	text := coverage.TextCharacters
	return text.Guarded != nil && text.Total != nil && *text.Guarded < *text.Total
}
