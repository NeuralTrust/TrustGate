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

package proxy

import (
	"encoding/json"
	"iter"
	"testing"

	"github.com/stretchr/testify/require"
)

func linesSeq(lines ...string) iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		for _, l := range lines {
			if !yield([]byte(l), nil) {
				return
			}
		}
	}
}

func collectLines(t *testing.T, seq iter.Seq2[[]byte, error]) []string {
	t.Helper()
	var out []string
	for line, err := range seq {
		require.NoError(t, err)
		out = append(out, string(line))
	}
	return out
}

func dataChunks(t *testing.T, lines []string) []map[string]any {
	t.Helper()
	var chunks []map[string]any
	for _, l := range lines {
		payload, ok := dataPayload([]byte(l))
		if !ok {
			continue
		}
		var m map[string]any
		require.NoError(t, json.Unmarshal(payload, &m))
		chunks = append(chunks, m)
	}
	return chunks
}

func chunkToolCalls(chunk map[string]any) []any {
	choices, _ := chunk["choices"].([]any)
	if len(choices) == 0 {
		return nil
	}
	choice, _ := choices[0].(map[string]any)
	delta, _ := choice["delta"].(map[string]any)
	calls, _ := delta["tool_calls"].([]any)
	return calls
}
