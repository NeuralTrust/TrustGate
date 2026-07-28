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

package promptcompression

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func allTransforms() Settings {
	cfg, err := parseConfig(map[string]any{
		"compress_json":        true,
		"normalize_whitespace": true,
		"strip_ansi":           true,
	})
	if err != nil {
		panic(err)
	}
	return cfg
}

func TestCompactJSONLossless(t *testing.T) {
	t.Parallel()
	pretty := "{\n  \"items\": [\n    {\"id\": 1, \"name\": \"a\"},\n    {\"id\": 2, \"name\": \"b\"}\n  ],\n  \"total\": 2\n}"
	out, changed := compressContent(pretty, allTransforms())
	require.True(t, changed)
	assert.Less(t, len(out), len(pretty))

	var before, after any
	require.NoError(t, json.Unmarshal([]byte(pretty), &before))
	require.NoError(t, json.Unmarshal([]byte(out), &after))
	assert.Equal(t, before, after, "compaction must preserve the decoded JSON value")
}

func TestCompactJSONInvalidUntouched(t *testing.T) {
	t.Parallel()
	broken := "{\"key\": unquoted}"
	out, changed := compressContent(broken, Settings{CompressJSON: true, MaxConsecutiveBlankLines: 1})
	assert.False(t, changed)
	assert.Equal(t, broken, out)
}

func TestFencedJSONCompacted(t *testing.T) {
	t.Parallel()
	content := "Here is the tool output:\n```json\n{\n  \"status\": \"ok\",\n  \"count\": 3\n}\n```\nDone."
	out, changed := compressContent(content, Settings{CompressJSON: true, MaxConsecutiveBlankLines: 1})
	require.True(t, changed)
	assert.Contains(t, out, "```json\n{\"status\":\"ok\",\"count\":3}\n```")
	assert.True(t, strings.HasPrefix(out, "Here is the tool output:\n"))
	assert.True(t, strings.HasSuffix(out, "\nDone."))
}

func TestFencedJSONInvalidBlockUntouched(t *testing.T) {
	t.Parallel()
	content := "```json\nnot json at all\n```"
	out, changed := compressContent(content, Settings{CompressJSON: true, MaxConsecutiveBlankLines: 1})
	assert.False(t, changed)
	assert.Equal(t, content, out)
}

func TestNormalizeWhitespace(t *testing.T) {
	t.Parallel()
	content := "line one   \n\n\n\nline two\t\n  indented stays"
	out, changed := compressContent(content, Settings{NormalizeWhitespace: true, MaxConsecutiveBlankLines: 1})
	require.True(t, changed)
	assert.Equal(t, "line one\n\nline two\n  indented stays", out)
}

func TestStripANSI(t *testing.T) {
	t.Parallel()
	content := "\x1b[31mERROR\x1b[0m build failed\n\x1b[2K\x1b[1Gretrying"
	out, changed := compressContent(content, Settings{StripANSI: true, MaxConsecutiveBlankLines: 1})
	require.True(t, changed)
	assert.Equal(t, "ERROR build failed\nretrying", out)
}

func TestMinLengthSkips(t *testing.T) {
	t.Parallel()
	cfg := allTransforms()
	cfg.MinLength = 1000
	content := "{ \"a\":  1 }"
	out, changed := compressContent(content, cfg)
	assert.False(t, changed)
	assert.Equal(t, content, out)
}

func TestDeterministicAndIdempotent(t *testing.T) {
	t.Parallel()
	cfg := allTransforms()
	content := "intro\n\n\n```json\n{ \"a\": [1, 2] }\n```\ntrailing   \n"
	first, changed := compressContent(content, cfg)
	require.True(t, changed)
	second, changedAgain := compressContent(first, cfg)
	assert.False(t, changedAgain, "compressing compressed output must be a no-op for cache stability")
	assert.Equal(t, first, second)
}

func TestProseUntouched(t *testing.T) {
	t.Parallel()
	content := "Explain quantum entanglement in simple terms."
	out, changed := compressContent(content, allTransforms())
	assert.False(t, changed)
	assert.Equal(t, content, out)
}
