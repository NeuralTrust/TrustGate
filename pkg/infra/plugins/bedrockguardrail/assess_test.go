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
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

func intervened(assessment types.GuardrailAssessment) *bedrockruntime.ApplyGuardrailOutput {
	return &bedrockruntime.ApplyGuardrailOutput{
		Action:      types.GuardrailActionGuardrailIntervened,
		Assessments: []types.GuardrailAssessment{assessment},
	}
}

func TestInspectFamilies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		output    *bedrockruntime.ApplyGuardrailOutput
		piiAction string
		block     *finding
		anonymize *finding
	}{
		{
			name: "topic blocked",
			output: intervened(types.GuardrailAssessment{
				TopicPolicy: &types.GuardrailTopicPolicyAssessment{
					Topics: []types.GuardrailTopic{{
						Action: types.GuardrailTopicPolicyActionBlocked,
						Name:   aws.String("Investment Advice"),
						Type:   types.GuardrailTopicTypeDeny,
					}},
				},
			}),
			piiAction: piiActionBlock,
			block: &finding{
				policy:    policyTopic,
				name:      "Investment Advice",
				matchType: string(types.GuardrailTopicTypeDeny),
				action:    string(types.GuardrailTopicPolicyActionBlocked),
			},
		},
		{
			name: "content blocked",
			output: intervened(types.GuardrailAssessment{
				ContentPolicy: &types.GuardrailContentPolicyAssessment{
					Filters: []types.GuardrailContentFilter{{
						Action: types.GuardrailContentPolicyActionBlocked,
						Type:   types.GuardrailContentFilterTypeHate,
					}},
				},
			}),
			piiAction: piiActionBlock,
			block: &finding{
				policy:    policyContent,
				name:      string(types.GuardrailContentFilterTypeHate),
				matchType: string(types.GuardrailContentFilterTypeHate),
				action:    string(types.GuardrailContentPolicyActionBlocked),
			},
		},
		{
			name: "custom word blocked",
			output: intervened(types.GuardrailAssessment{
				WordPolicy: &types.GuardrailWordPolicyAssessment{
					CustomWords: []types.GuardrailCustomWord{{
						Action: types.GuardrailWordPolicyActionBlocked,
						Match:  aws.String("forbidden"),
					}},
				},
			}),
			piiAction: piiActionBlock,
			block: &finding{
				policy:    policyWord,
				name:      "forbidden",
				matchType: matchTypeCustomWord,
				action:    string(types.GuardrailWordPolicyActionBlocked),
			},
		},
		{
			name: "managed word blocked",
			output: intervened(types.GuardrailAssessment{
				WordPolicy: &types.GuardrailWordPolicyAssessment{
					ManagedWordLists: []types.GuardrailManagedWord{{
						Action: types.GuardrailWordPolicyActionBlocked,
						Match:  aws.String("damn"),
						Type:   types.GuardrailManagedWordTypeProfanity,
					}},
				},
			}),
			piiAction: piiActionBlock,
			block: &finding{
				policy:    policyWord,
				name:      "damn",
				matchType: string(types.GuardrailManagedWordTypeProfanity),
				action:    string(types.GuardrailWordPolicyActionBlocked),
			},
		},
		{
			name: "contextual grounding blocked",
			output: intervened(types.GuardrailAssessment{
				ContextualGroundingPolicy: &types.GuardrailContextualGroundingPolicyAssessment{
					Filters: []types.GuardrailContextualGroundingFilter{{
						Action:    types.GuardrailContextualGroundingPolicyActionBlocked,
						Type:      types.GuardrailContextualGroundingFilterTypeGrounding,
						Score:     aws.Float64(0.1),
						Threshold: aws.Float64(0.8),
					}},
				},
			}),
			piiAction: piiActionBlock,
			block: &finding{
				policy:    policyContextualGrounding,
				matchType: string(types.GuardrailContextualGroundingFilterTypeGrounding),
				action:    string(types.GuardrailContextualGroundingPolicyActionBlocked),
			},
		},
		{
			name: "pii entity blocked with pii_action block",
			output: intervened(types.GuardrailAssessment{
				SensitiveInformationPolicy: &types.GuardrailSensitiveInformationPolicyAssessment{
					PiiEntities: []types.GuardrailPiiEntityFilter{{
						Action: types.GuardrailSensitiveInformationPolicyActionBlocked,
						Match:  aws.String("john@example.com"),
						Type:   types.GuardrailPiiEntityTypeEmail,
					}},
				},
			}),
			piiAction: piiActionBlock,
			block: &finding{
				policy:    policySensitiveInformation,
				name:      "john@example.com",
				matchType: string(types.GuardrailPiiEntityTypeEmail),
				action:    string(types.GuardrailSensitiveInformationPolicyActionBlocked),
			},
		},
		{
			name: "pii entity anonymized with pii_action block falls to block",
			output: intervened(types.GuardrailAssessment{
				SensitiveInformationPolicy: &types.GuardrailSensitiveInformationPolicyAssessment{
					PiiEntities: []types.GuardrailPiiEntityFilter{{
						Action: types.GuardrailSensitiveInformationPolicyActionAnonymized,
						Match:  aws.String("john@example.com"),
						Type:   types.GuardrailPiiEntityTypeEmail,
					}},
				},
			}),
			piiAction: piiActionBlock,
			block: &finding{
				policy:    policySensitiveInformation,
				name:      "john@example.com",
				matchType: string(types.GuardrailPiiEntityTypeEmail),
				action:    string(types.GuardrailSensitiveInformationPolicyActionAnonymized),
			},
		},
		{
			name: "pii entity anonymized with pii_action anonymize",
			output: intervened(types.GuardrailAssessment{
				SensitiveInformationPolicy: &types.GuardrailSensitiveInformationPolicyAssessment{
					PiiEntities: []types.GuardrailPiiEntityFilter{{
						Action: types.GuardrailSensitiveInformationPolicyActionAnonymized,
						Match:  aws.String("john@example.com"),
						Type:   types.GuardrailPiiEntityTypeEmail,
					}},
				},
			}),
			piiAction: piiActionAnonymize,
			anonymize: &finding{
				policy:    policySensitiveInformation,
				name:      "john@example.com",
				matchType: string(types.GuardrailPiiEntityTypeEmail),
				action:    string(types.GuardrailSensitiveInformationPolicyActionAnonymized),
			},
		},
		{
			name: "pii entity blocked with pii_action anonymize falls back to block",
			output: intervened(types.GuardrailAssessment{
				SensitiveInformationPolicy: &types.GuardrailSensitiveInformationPolicyAssessment{
					PiiEntities: []types.GuardrailPiiEntityFilter{{
						Action: types.GuardrailSensitiveInformationPolicyActionBlocked,
						Match:  aws.String("john@example.com"),
						Type:   types.GuardrailPiiEntityTypeEmail,
					}},
				},
			}),
			piiAction: piiActionAnonymize,
			block: &finding{
				policy:    policySensitiveInformation,
				name:      "john@example.com",
				matchType: string(types.GuardrailPiiEntityTypeEmail),
				action:    string(types.GuardrailSensitiveInformationPolicyActionBlocked),
			},
		},
		{
			name: "regex anonymized uses name fallback",
			output: intervened(types.GuardrailAssessment{
				SensitiveInformationPolicy: &types.GuardrailSensitiveInformationPolicyAssessment{
					Regexes: []types.GuardrailRegexFilter{{
						Action: types.GuardrailSensitiveInformationPolicyActionAnonymized,
						Name:   aws.String("ssn-pattern"),
					}},
				},
			}),
			piiAction: piiActionAnonymize,
			anonymize: &finding{
				policy:    policySensitiveInformation,
				name:      "ssn-pattern",
				matchType: matchTypeRegex,
				action:    string(types.GuardrailSensitiveInformationPolicyActionAnonymized),
			},
		},
		{
			name: "topic block wins over pii anonymize ordering",
			output: intervened(types.GuardrailAssessment{
				TopicPolicy: &types.GuardrailTopicPolicyAssessment{
					Topics: []types.GuardrailTopic{{
						Action: types.GuardrailTopicPolicyActionBlocked,
						Name:   aws.String("Investment Advice"),
						Type:   types.GuardrailTopicTypeDeny,
					}},
				},
				SensitiveInformationPolicy: &types.GuardrailSensitiveInformationPolicyAssessment{
					PiiEntities: []types.GuardrailPiiEntityFilter{{
						Action: types.GuardrailSensitiveInformationPolicyActionAnonymized,
						Match:  aws.String("john@example.com"),
						Type:   types.GuardrailPiiEntityTypeEmail,
					}},
				},
			}),
			piiAction: piiActionAnonymize,
			block: &finding{
				policy:    policyTopic,
				name:      "Investment Advice",
				matchType: string(types.GuardrailTopicTypeDeny),
				action:    string(types.GuardrailTopicPolicyActionBlocked),
			},
			anonymize: &finding{
				policy:    policySensitiveInformation,
				name:      "john@example.com",
				matchType: string(types.GuardrailPiiEntityTypeEmail),
				action:    string(types.GuardrailSensitiveInformationPolicyActionAnonymized),
			},
		},
		{
			name: "nil pointers tolerated",
			output: intervened(types.GuardrailAssessment{
				TopicPolicy: &types.GuardrailTopicPolicyAssessment{
					Topics: []types.GuardrailTopic{{
						Action: types.GuardrailTopicPolicyActionBlocked,
						Type:   types.GuardrailTopicTypeDeny,
					}},
				},
			}),
			piiAction: piiActionBlock,
			block: &finding{
				policy:    policyTopic,
				matchType: string(types.GuardrailTopicTypeDeny),
				action:    string(types.GuardrailTopicPolicyActionBlocked),
			},
		},
		{
			name: "no intervention is empty",
			output: &bedrockruntime.ApplyGuardrailOutput{
				Action: types.GuardrailActionNone,
				Assessments: []types.GuardrailAssessment{{
					ContentPolicy: &types.GuardrailContentPolicyAssessment{},
				}},
			},
			piiAction: piiActionBlock,
		},
		{
			name:      "nil output is empty",
			output:    nil,
			piiAction: piiActionBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			res := inspect(tt.output, tt.piiAction)
			assertFinding(t, "block", res.block, tt.block)
			assertFinding(t, "anonymize", res.anonymize, tt.anonymize)
		})
	}
}

func TestInspectIntervenedFlag(t *testing.T) {
	t.Parallel()
	res := inspect(&bedrockruntime.ApplyGuardrailOutput{Action: types.GuardrailActionGuardrailIntervened}, piiActionBlock)
	if !res.intervened {
		t.Fatal("expected intervened true")
	}
	res = inspect(&bedrockruntime.ApplyGuardrailOutput{Action: types.GuardrailActionNone}, piiActionBlock)
	if res.intervened {
		t.Fatal("expected intervened false")
	}
}

func TestBuildApplyInput(t *testing.T) {
	t.Parallel()
	cfg := Settings{GuardrailID: "gr-123", Version: "DRAFT"}
	in := buildApplyInput(cfg, "hello", types.GuardrailContentSourceInput)
	if aws.ToString(in.GuardrailIdentifier) != "gr-123" {
		t.Fatalf("GuardrailIdentifier = %q", aws.ToString(in.GuardrailIdentifier))
	}
	if aws.ToString(in.GuardrailVersion) != "DRAFT" {
		t.Fatalf("GuardrailVersion = %q", aws.ToString(in.GuardrailVersion))
	}
	if in.Source != types.GuardrailContentSourceInput {
		t.Fatalf("Source = %q", in.Source)
	}
	if len(in.Content) != 1 {
		t.Fatalf("Content len = %d, want 1", len(in.Content))
	}
	block, ok := in.Content[0].(*types.GuardrailContentBlockMemberText)
	if !ok {
		t.Fatalf("Content[0] type = %T", in.Content[0])
	}
	if aws.ToString(block.Value.Text) != "hello" {
		t.Fatalf("text = %q", aws.ToString(block.Value.Text))
	}
}

func assertFinding(t *testing.T, label string, got, want *finding) {
	t.Helper()
	switch {
	case want == nil && got == nil:
		return
	case want == nil && got != nil:
		t.Fatalf("%s = %+v, want nil", label, *got)
	case want != nil && got == nil:
		t.Fatalf("%s = nil, want %+v", label, *want)
	case *got != *want:
		t.Fatalf("%s = %+v, want %+v", label, *got, *want)
	}
}
