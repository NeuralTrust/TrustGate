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

package oauth

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The MCP config is copied into a client as it is: the placeholder as typed,
// not the escape encoding/json writes for HTML, and valid JSON.
func TestPersonalKeySnippets_MCPConfigIsPlainJSON(t *testing.T) {
	snippets := personalKeySnippets("https://gw.example/store/mcp", "https://gw.example/store/v1")
	require.Equal(t, []string{"sdk", "openai", "mcp"}, []string{snippets[0].ID, snippets[1].ID, snippets[2].ID})
	mcp := snippets[2].Code
	require.NotContains(t, mcp, "\\u003c", "the placeholder is not escaped for HTML")
	require.Contains(t, mcp, `"Authorization": "Bearer <your-api-key>"`)
	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(mcp), &parsed))
	require.Less(t, strings.Index(mcp, `"url"`), strings.Index(mcp, `"headers"`), "the url reads first")
}

// Each snippet is drawn line by line, numbered, with what the reader fills in
// drawn apart from the code around it.
func TestHighlightSnippet_ColoursAndPlaceholders(t *testing.T) {
	lines := highlightSnippet("# pip install openai\nfrom openai import OpenAI\n\nclient = OpenAI(api_key=\"<your-api-key>\")\n  \"url\": \"x\"")
	require.Len(t, lines, 5)
	require.Equal(t, 5, lines[4].N)
	require.Equal(t, []snippetToken{{Kind: "com", Text: "# pip install openai"}}, lines[0].Tokens)
	require.Equal(t, []snippetToken{{Kind: "kw", Text: "from"}, {Text: " openai "}, {Kind: "kw", Text: "import"}, {Text: " OpenAI"}}, lines[1].Tokens)
	require.Empty(t, lines[2].Tokens)
	require.Equal(t, []snippetToken{
		{Text: "client = OpenAI(api_key="}, {Kind: "str", Text: `"`}, {Kind: "ph", Text: "<your-api-key>"}, {Kind: "str", Text: `"`}, {Text: ")"},
	}, lines[3].Tokens)
	require.Equal(t, []snippetToken{{Text: "  "}, {Kind: "key", Text: `"url"`}, {Text: ": "}, {Kind: "str", Text: `"x"`}}, lines[4].Tokens)
}
