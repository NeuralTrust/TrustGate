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

package toolallowlist

import (
	"slices"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

var (
	openAIBuiltinTools = []string{
		"web_search", "web_search_preview", "web_search_preview_2025_03_11", "file_search",
		"code_interpreter", "computer_use_preview", "mcp", "local_shell", "image_generation",
	}
	geminiBuiltinTools = []string{
		"googleSearch", "google_search", "googleSearchRetrieval", "google_search_retrieval",
		"codeExecution", "code_execution", "urlContext", "url_context",
	}
	anthropicServerToolFamilies = []string{"web_search_", "web_fetch_", "code_execution_", "bash_", "text_editor_", "computer_"}
)

// isBuiltinTool reports whether kind names a tool the provider behind ad
// runs itself. Anthropic versions its server tools by date, as in
// web_search_20250305.
func isBuiltinTool(ad adapter.RequestAdapter, kind string) bool {
	switch ad.(type) {
	case *adapter.OpenAIResponsesAdapter:
		return slices.Contains(openAIBuiltinTools, kind)
	case *adapter.GeminiAdapter:
		return slices.Contains(geminiBuiltinTools, kind)
	case *adapter.BedrockAdapter:
		return kind == "systemTool"
	case *adapter.AnthropicAdapter:
		for _, family := range anthropicServerToolFamilies {
			if version, ok := strings.CutPrefix(kind, family); ok && len(version) == 8 && isDigits(version) {
				return true
			}
		}
	}
	return false
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
