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

package modelallowlist

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		want    bool
	}{
		{name: "exact match", pattern: "gpt-4o", input: "gpt-4o", want: true},
		{name: "exact mismatch", pattern: "gpt-5", input: "gpt-5-turbo", want: false},
		{name: "suffix wildcard matches base", pattern: "gpt-5*", input: "gpt-5", want: true},
		{name: "suffix wildcard matches family", pattern: "gpt-5*", input: "gpt-5-mini", want: true},
		{name: "prefix wildcard", pattern: "*turbo", input: "gpt-4-turbo", want: true},
		{name: "prefix wildcard no match", pattern: "*turbo", input: "gpt-4-mini", want: false},
		{name: "wildcard matches empty run", pattern: "claude-sonnet-*", input: "claude-sonnet-", want: true},
		{name: "wildcard matches any run", pattern: "claude-sonnet-*", input: "claude-sonnet-4.6", want: true},
		{name: "interior scan a*b*c", pattern: "a*b*c", input: "axxbyyc", want: true},
		{name: "interior scan a*b*c no tail", pattern: "a*b*c", input: "axxbyyd", want: false},
		{name: "interior scan a*b*c missing middle", pattern: "a*b*c", input: "axxc", want: false},
		{name: "double star matches everything", pattern: "**", input: "anything-at-all", want: true},
		{name: "double star matches empty", pattern: "**", input: "", want: true},
		{name: "case sensitive mismatch", pattern: "gpt-5*", input: "GPT-5", want: false},
		{name: "bedrock arn literal match", pattern: "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude", input: "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude", want: true},
		{name: "bedrock arn glob match", pattern: "arn:aws:bedrock:*", input: "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude", want: true},
		{name: "bedrock arn glob no match", pattern: "arn:aws:bedrock:*", input: "arn:aws:sagemaker:us-east-1", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, matchGlob(tt.pattern, tt.input))
		})
	}
}

func TestMatchAny(t *testing.T) {
	patterns := []string{"gpt-5*", "claude-sonnet-*"}
	tests := []struct {
		name        string
		input       string
		wantMatched string
		wantOK      bool
	}{
		{name: "first pattern", input: "gpt-5-turbo", wantMatched: "gpt-5*", wantOK: true},
		{name: "second pattern", input: "claude-sonnet-4.6", wantMatched: "claude-sonnet-*", wantOK: true},
		{name: "no match", input: "mistral-large", wantMatched: "", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, ok := matchAny(tt.input, patterns)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantMatched, matched)
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		wantErr  bool
	}{
		{
			name:     "valid reject defaults behavior",
			settings: map[string]any{"allowed_models": []string{"gpt-5*"}},
		},
		{
			name:     "valid explicit reject",
			settings: map[string]any{"allowed_models": []string{"gpt-5*"}, "behavior_on_disallowed": "reject"},
		},
		{
			name: "valid substitute in allowlist",
			settings: map[string]any{
				"allowed_models":         []string{"gpt-5*"},
				"behavior_on_disallowed": "substitute",
				"substitute_with":        "gpt-5",
			},
		},
		{
			name:     "valid default model in allowlist",
			settings: map[string]any{"allowed_models": []string{"gpt-5*"}, "default_model": "gpt-5"},
		},
		{
			name:     "empty allowlist",
			settings: map[string]any{"allowed_models": []string{}},
			wantErr:  true,
		},
		{
			name:     "missing allowlist",
			settings: map[string]any{"behavior_on_disallowed": "reject"},
			wantErr:  true,
		},
		{
			name:     "blank entry",
			settings: map[string]any{"allowed_models": []string{"gpt-5*", "  "}},
			wantErr:  true,
		},
		{
			name:     "bad behavior enum",
			settings: map[string]any{"allowed_models": []string{"gpt-5*"}, "behavior_on_disallowed": "drop"},
			wantErr:  true,
		},
		{
			name:     "substitute missing substitute_with",
			settings: map[string]any{"allowed_models": []string{"gpt-5*"}, "behavior_on_disallowed": "substitute"},
			wantErr:  true,
		},
		{
			name: "substitute_with not in allowlist",
			settings: map[string]any{
				"allowed_models":         []string{"gpt-5*"},
				"behavior_on_disallowed": "substitute",
				"substitute_with":        "claude-3",
			},
			wantErr: true,
		},
		{
			name:     "default_model not in allowlist",
			settings: map[string]any{"allowed_models": []string{"gpt-5*"}, "default_model": "claude-3"},
			wantErr:  true,
		},
		{
			name: "substitute_with set under reject",
			settings: map[string]any{
				"allowed_models":         []string{"gpt-5*"},
				"behavior_on_disallowed": "reject",
				"substitute_with":        "gpt-5",
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
	cfg, err := parseConfig(map[string]any{"allowed_models": []string{"gpt-5*"}})
	require.NoError(t, err)
	assert.Equal(t, behaviorReject, cfg.Behavior)
}

func TestObserveDecision(t *testing.T) {
	assert.Equal(t, decisionWouldReject, observeDecision(behaviorReject))
	assert.Equal(t, decisionWouldSubstitute, observeDecision(behaviorSubstitute))
}

func TestModelAllowlistDataDecisions(t *testing.T) {
	data := ModelAllowlistData{
		RequestedModel:  "gpt-3.5",
		Decision:        decisionSubstituted,
		MatchedPattern:  "gpt-5*",
		SubstitutedWith: "gpt-5",
		Behavior:        string(behaviorSubstitute),
	}
	assert.Equal(t, decisionSubstituted, data.Decision)
	assert.NotEqual(t, decisionAllowed, data.Decision)
	assert.NotEqual(t, decisionRejected, data.Decision)
	assert.NotEqual(t, decisionDefaulted, data.Decision)
}
