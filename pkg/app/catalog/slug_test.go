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

package catalog

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSlugCandidates(t *testing.T) {
	tests := []struct {
		name   string
		models []string
		want   []string
	}{
		{
			name:   "a regional inference profile also tries the bare model",
			models: []string{"eu.amazon.nova-lite-v1:0"},
			want:   []string{"eu.amazon.nova-lite-v1:0", "amazon.nova-lite-v1:0"},
		},
		{
			// Bedrock writes the date without separators, so only the
			// geography comes off — the deployment-date rule needs dashes.
			name:   "a dated Bedrock profile only loses its geography",
			models: []string{"us.anthropic.claude-haiku-4-5-20251001-v1:0"},
			want: []string{
				"us.anthropic.claude-haiku-4-5-20251001-v1:0",
				"anthropic.claude-haiku-4-5-20251001-v1:0",
			},
		},
		{
			name:   "a dated deployment still drops its date",
			models: []string{"gpt-4o-2024-05-13"},
			want:   []string{"gpt-4o-2024-05-13", "gpt-4o"},
		},
		{
			name:   "a model that only looks prefixed keeps its name",
			models: []string{"mistral.devstral-2-123b"},
			want:   []string{"mistral.devstral-2-123b"},
		},
		{
			name:   "duplicates across models collapse",
			models: []string{"eu.amazon.nova-lite-v1:0", "amazon.nova-lite-v1:0", ""},
			want:   []string{"eu.amazon.nova-lite-v1:0", "amazon.nova-lite-v1:0"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, SlugCandidates(tc.models...))
		})
	}
}
