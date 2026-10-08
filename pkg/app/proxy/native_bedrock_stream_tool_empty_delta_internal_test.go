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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const claudeToolEmail = "jane.doe@example.com"

// Claude opens a tool call with an empty input delta, and may send others
// between the fragments. They carry no tool call to the guard, which must not
// take them for a frame it cannot rewrite.
func TestNativeToolMask_EmptyInputDeltasAreLeftAsTheyAre(t *testing.T) {
	t.Parallel()
	for name, fragments := range map[string][]string{
		"empty first":  {``, `{"to": "`, `jane.doe@exa`, `mple.com"`, `}`},
		"empty middle": {`{"to": "`, `jane.doe@exa`, ``, `mple.com"`, `}`},
		"empty last":   {`{"to": "`, `jane.doe@exa`, `mple.com"`, `}`, ``},
		"empty around": {``, `{"to": "`, `jane.doe@exa`, ``, `mple.com"`, `}`, ``},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			frames := append([][]byte{
				testEventFrame(t, "messageStart", `{"role":"assistant"}`),
				deltaFrame(t, "I will send the email now."),
				testEventFrame(t, "contentBlockStop", `{"contentBlockIndex":0}`),
			}, converseToolFrames(t, 1, fragments...)...)
			frames = append(frames,
				testEventFrame(t, "messageStop", `{"stopReason":"tool_use"}`),
				testEventFrame(t, "metadata", `{"usage":{"inputTokens":10,"outputTokens":20,"totalTokens":30},"metrics":{"latencyMs":100}}`))

			runner := &maskRunner{from: claudeToolEmail, to: "<EMAIL>"}
			got, pe, rt := runNativeGuardTraced(t, nativeGuardFor(runner, toolBlocks), frames)
			require.Nil(t, pe)
			require.Len(t, got, len(frames), "no frame is dropped")
			assert.Empty(t, streamFailedOpenEntries(rt), "the mask applied, nothing failed open")

			released := fragmentsOf(got)
			require.Len(t, released, len(fragments))
			var parsed map[string]string
			require.NoError(t, json.Unmarshal([]byte(strings.Join(released, "")), &parsed), "an SDK parses the joined input")
			assert.Equal(t, map[string]string{"to": "<EMAIL>"}, parsed)
			assert.NotContains(t, releasedText(t, got), "jane.doe")
			assert.NotContains(t, releasedText(t, got), "example.com")

			for i, f := range fragments {
				if f == "" {
					assert.Empty(t, released[i], "an empty delta stays empty")
				}
			}
			for i := range frames {
				if in, ok := fragmentsOfFrame(frames[i]); ok && in == "" {
					assert.Equal(t, frames[i], got[i], "an empty delta frame is released as it came")
				}
			}
		})
	}
}

func fragmentsOfFrame(frame []byte) (string, bool) {
	out := fragmentsOf([][]byte{frame})
	if len(out) == 0 {
		return "", false
	}
	return out[0], true
}
