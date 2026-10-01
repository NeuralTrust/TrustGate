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

package adapter_test

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
)

func TestIsChatRequest_EmptyCapabilityFallsBackToFormat(t *testing.T) {
	tests := []struct {
		format adapter.Format
		want   bool
	}{
		{format: adapter.FormatOpenAI, want: true},
		{format: adapter.FormatOpenAIResponses, want: true},
		{format: adapter.FormatAnthropic, want: true},
		{format: adapter.FormatGemini, want: true},
		{format: adapter.FormatCohere, want: true},
		{format: adapter.FormatMistral, want: true},
		{format: adapter.FormatOpenAIEmbeddings},
		{format: adapter.FormatOpenAIFiles},
		{format: adapter.FormatOpenAIImages},
		{format: adapter.FormatOpenAIAudio},
		{format: adapter.FormatCohereEmbed},
		{format: adapter.FormatCohereRerank},
		{format: adapter.FormatVertexEmbed},
		{format: adapter.FormatBedrockTitanEmbed},
	}
	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			assert.Equal(t, tt.want, adapter.IsChatRequest("", tt.format))
		})
	}
}
