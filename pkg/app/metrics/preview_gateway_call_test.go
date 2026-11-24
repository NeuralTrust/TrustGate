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

package metrics

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/stretchr/testify/assert"
)

// trustgate_call is previewed as what it called: a tool with that tool's own
// arguments, or an agent with the message sent to it.
func TestToolCallPreview_GatewayCall(t *testing.T) {
	t.Parallel()
	for label, tc := range map[string]struct {
		tool, body, want string
	}{
		"a tool": {
			tool: "linear_save_issue",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"trustgate_call","arguments":{"tool":"linear_save_issue","arguments":{"title":"Login bug"}}}}`,
			want: "linear_save_issue(Login bug)",
		},
		"an agent": {
			tool: "Research",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"trustgate_call","arguments":{"agent":"research","message":"Summarise Q3"}}}`,
			want: "Summarise Q3",
		},
	} {
		got := toolCallPreview(&events.MCP{Method: "tools/call", Tool: tc.tool}, tc.body)
		assert.Equal(t, tc.want, got, label)
	}
}
