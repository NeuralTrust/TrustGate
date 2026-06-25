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
	block      *finding
	anonymize  *finding
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
				name:      aws.ToString(w.Match),
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
				name:      aws.ToString(w.Match),
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
		classifyPII(e.Action, aws.ToString(e.Match), string(e.Type), piiAction, res)
	}
	for i := range p.Regexes {
		r := p.Regexes[i]
		name := aws.ToString(r.Match)
		if name == "" {
			name = aws.ToString(r.Name)
		}
		classifyPII(r.Action, name, matchTypeRegex, piiAction, res)
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
