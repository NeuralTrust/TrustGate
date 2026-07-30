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

package trustguard

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func TestStreamAssistantTextOpenAICompletions(t *testing.T) {
	t.Parallel()

	reg := adapter.NewRegistry()
	sse := "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hel\"}}]}\n" +
		"data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"lo\"}}]}\n" +
		"data: [DONE]\n"
	got := streamAssistantText(reg, []byte(sse), adapter.FormatOpenAI)
	if got != "hello" {
		t.Fatalf("streamAssistantText = %q, want %q", got, "hello")
	}
}

func TestStreamAssistantTextEmpty(t *testing.T) {
	t.Parallel()

	reg := adapter.NewRegistry()
	if got := streamAssistantText(reg, nil, adapter.FormatOpenAI); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
	if got := streamAssistantText(nil, []byte("data: {}\n"), adapter.FormatOpenAI); got != "" {
		t.Fatalf("nil registry got %q, want empty", got)
	}
}
