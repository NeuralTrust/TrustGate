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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// streamAssistantText reassembles assistant text from a buffered SSE body using
// per-chunk DecodeStreamChunk. Returns empty when the body is not SSE or yields
// no text deltas (caller should fall back to DecodeResponse).
func streamAssistantText(reg *adapter.Registry, body []byte, format adapter.Format) string {
	if reg == nil || len(body) == 0 {
		return ""
	}
	var b strings.Builder
	for _, line := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		chunk, err := reg.DecodeStreamChunkFor([]byte(payload), format)
		if err != nil || chunk == nil {
			continue
		}
		if d := strings.TrimSpace(chunk.Delta); d != "" {
			b.WriteString(chunk.Delta)
		}
	}
	return b.String()
}
