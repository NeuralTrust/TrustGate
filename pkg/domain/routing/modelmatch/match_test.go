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

package modelmatch_test

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/modelmatch"
	"github.com/stretchr/testify/assert"
)

func TestMatches(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		want    bool
	}{
		{name: "exact match", pattern: "gpt-4o", input: "gpt-4o", want: true},
		{name: "exact mismatch", pattern: "gpt-5", input: "gpt-5-turbo", want: false},
		{name: "no star no match", pattern: "gpt", input: "gpt-5", want: false},
		{name: "suffix wildcard matches base", pattern: "gpt-5*", input: "gpt-5", want: true},
		{name: "suffix wildcard matches family", pattern: "gpt-5*", input: "gpt-5-mini", want: true},
		{name: "prefix wildcard", pattern: "*turbo", input: "gpt-4-turbo", want: true},
		{name: "prefix wildcard no match", pattern: "*turbo", input: "gpt-4-mini", want: false},
		{name: "leading star", pattern: "*-mini", input: "gpt-5-mini", want: true},
		{name: "leading star no match", pattern: "*-mini", input: "gpt-5", want: false},
		{name: "middle star", pattern: "gpt-*-mini", input: "gpt-5-mini", want: true},
		{name: "middle star no match", pattern: "gpt-*-mini", input: "gpt-5-nano", want: false},
		{name: "wildcard matches empty run", pattern: "claude-sonnet-*", input: "claude-sonnet-", want: true},
		{name: "wildcard matches any run", pattern: "claude-sonnet-*", input: "claude-sonnet-4.6", want: true},
		{name: "opus family", pattern: "claude-opus-*", input: "claude-opus-4-1", want: true},
		{name: "opus family excludes sonnet", pattern: "claude-opus-*", input: "claude-sonnet-4", want: false},
		{name: "interior scan a*b*c", pattern: "a*b*c", input: "axxbyyc", want: true},
		{name: "interior scan a*b*c no tail", pattern: "a*b*c", input: "axxbyyd", want: false},
		{name: "interior scan a*b*c missing middle", pattern: "a*b*c", input: "axxc", want: false},
		{name: "interior scan a*b*c truncated", pattern: "a*b*c", input: "axxbyy", want: false},
		{name: "only star matches anything", pattern: "*", input: "anything", want: true},
		{name: "double star matches everything", pattern: "**", input: "anything-at-all", want: true},
		{name: "double star matches empty", pattern: "**", input: "", want: true},
		{name: "case sensitive mismatch", pattern: "gpt-5*", input: "GPT-5", want: false},
		{name: "anchored prefix rejects lead-in", pattern: "gpt-*", input: "xgpt-4o", want: false},
		{name: "dot is literal not any char", pattern: "gpt-5.*", input: "gpt-5-mini", want: false},
		{name: "dot is literal and matches a dot", pattern: "gpt-5.*", input: "gpt-5.1", want: true},
		{name: "dot pattern excludes bare base", pattern: "gpt-5.*", input: "gpt-5", want: false},
		{name: "question mark is literal", pattern: "gpt-5?", input: "gpt-5a", want: false},
		{name: "character class is literal", pattern: "gpt-[45]", input: "gpt-4", want: false},
		{
			name:    "bedrock arn literal match",
			pattern: "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude",
			input:   "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude",
			want:    true,
		},
		{
			name:    "bedrock arn glob match",
			pattern: "arn:aws:bedrock:*",
			input:   "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude",
			want:    true,
		},
		{
			name:    "bedrock arn glob no match",
			pattern: "arn:aws:bedrock:*",
			input:   "arn:aws:sagemaker:us-east-1",
			want:    false,
		},
		{
			name:    "wildcard crosses a slash",
			pattern: "meta-llama/*",
			input:   "meta-llama/Llama-3.1-8B-Instruct",
			want:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, modelmatch.Matches(tt.pattern, tt.input))
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
			matched, ok := modelmatch.MatchAny(tt.input, patterns)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantMatched, matched)
		})
	}
}

func TestMatchAnyFirstMatchWins(t *testing.T) {
	matched, ok := modelmatch.MatchAny("gpt-5-mini", []string{"gpt-*", "gpt-5-mini"})
	assert.True(t, ok)
	assert.Equal(t, "gpt-*", matched)
}

func TestMatchAnyRejectsPatternSubject(t *testing.T) {
	tests := []struct {
		name     string
		subject  string
		patterns []string
	}{
		{name: "pattern satisfying itself", subject: "gpt-*", patterns: []string{"gpt-*"}},
		{name: "bare wildcard subject", subject: "*", patterns: []string{"*"}},
		{name: "wildcard subject against open pattern", subject: "gpt-*", patterns: []string{"*"}},
		{name: "wildcard subject against literal", subject: "gpt-*", patterns: []string{"gpt-4o"}},
		{name: "embedded wildcard subject", subject: "gpt-*-mini", patterns: []string{"gpt-*"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, ok := modelmatch.MatchAny(tt.subject, tt.patterns)
			assert.False(t, ok, "a pattern must never satisfy an allow-list")
			assert.Empty(t, matched)
		})
	}
}

func TestMatchAnyDeniesUnintendedModels(t *testing.T) {
	tests := []struct {
		name     string
		subject  string
		patterns []string
	}{
		{name: "other family", subject: "claude-3-opus", patterns: []string{"gpt-*"}},
		{name: "prefix stops short", subject: "gpt", patterns: []string{"gpt-*"}},
		{name: "case differs", subject: "GPT-4O", patterns: []string{"gpt-*"}},
		{name: "lead-in before prefix", subject: "xgpt-4o", patterns: []string{"gpt-*"}},
		{name: "suffix pattern needs the suffix", subject: "gpt-4o", patterns: []string{"*-mini"}},
		{name: "dash is not a dot", subject: "gpt-5-mini", patterns: []string{"gpt-5.*"}},
		{name: "empty allow-list matches nothing", subject: "gpt-4o", patterns: nil},
		{name: "empty subject", subject: "", patterns: []string{"gpt-*"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := modelmatch.MatchAny(tt.subject, tt.patterns)
			assert.False(t, ok)
		})
	}
}

func TestMatchAnyAllowsEmptyTail(t *testing.T) {
	matched, ok := modelmatch.MatchAny("gpt-", []string{"gpt-*"})
	assert.True(t, ok, "a trailing wildcard matches the empty run by design")
	assert.Equal(t, "gpt-*", matched)
}
