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

package llmcost

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveDowngrade(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		target   string
		allowed  []string
		want     string
		wantOK   bool
	}{
		{name: "bare same provider", provider: "openai", target: "gpt-4o-mini", want: "gpt-4o-mini", wantOK: true},
		{name: "qualified same provider", provider: "openai", target: "@openai/gpt-4o-mini", want: "gpt-4o-mini", wantOK: true},
		{name: "qualified cross provider", provider: "openai", target: "@anthropic/claude-3-haiku"},
		{name: "pool target", provider: "openai", target: "pool:fast"},
		{name: "empty target", provider: "openai", target: ""},
		{name: "allowed contains target", provider: "openai", target: "gpt-4o-mini", allowed: []string{"gpt-4o", "gpt-4o-mini"}, want: "gpt-4o-mini", wantOK: true},
		{name: "allowed excludes target", provider: "openai", target: "gpt-4o-mini", allowed: []string{"gpt-4o"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ResolveDowngrade(tt.provider, tt.target, tt.allowed)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}
