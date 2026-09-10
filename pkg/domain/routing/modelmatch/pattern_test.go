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
	"github.com/stretchr/testify/require"
)

func TestIsPattern(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "literal", input: "gpt-4o", want: false},
		{name: "empty", input: "", want: false},
		{name: "dotted literal", input: "gpt-5.1", want: false},
		{name: "bedrock arn", input: "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude", want: false},
		{name: "trailing wildcard", input: "gpt-*", want: true},
		{name: "leading wildcard", input: "*-mini", want: true},
		{name: "interior wildcard", input: "gpt-*-mini", want: true},
		{name: "bare wildcard", input: "*", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, modelmatch.IsPattern(tt.input))
		})
	}
}

func TestValidateEntry(t *testing.T) {
	tests := []struct {
		name    string
		entry   string
		wantErr error
	}{
		{name: "literal", entry: "gpt-4o"},
		{name: "trailing wildcard", entry: "gpt-*"},
		{name: "leading wildcard", entry: "*-mini"},
		{name: "interior wildcard", entry: "*turbo*"},
		{name: "dotted pattern", entry: "gpt-5.*"},
		{name: "arn pattern", entry: "arn:aws:bedrock:*"},
		{name: "empty", entry: "", wantErr: modelmatch.ErrBlankEntry},
		{name: "whitespace only", entry: "   ", wantErr: modelmatch.ErrBlankEntry},
		{name: "padded", entry: " gpt-* ", wantErr: modelmatch.ErrPaddedEntry},
		{name: "trailing space", entry: "gpt-* ", wantErr: modelmatch.ErrPaddedEntry},
		{name: "bare wildcard", entry: "*", wantErr: modelmatch.ErrWildcardOnly},
		{name: "double wildcard", entry: "**", wantErr: modelmatch.ErrWildcardOnly},
		{name: "triple wildcard", entry: "***", wantErr: modelmatch.ErrWildcardOnly},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := modelmatch.ValidateEntry(tt.entry)
			if tt.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestRequireConcrete(t *testing.T) {
	require.NoError(t, modelmatch.RequireConcrete("default", "gpt-4o-mini"))
	require.NoError(t, modelmatch.RequireConcrete("default", ""))

	err := modelmatch.RequireConcrete("default", "gpt-*")
	require.ErrorIs(t, err, modelmatch.ErrPatternNotModel)
	assert.Contains(t, err.Error(), "default")
	assert.Contains(t, err.Error(), "gpt-*")
}
