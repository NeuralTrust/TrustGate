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

package azurecontentsafety

import (
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const turnSeparator = "\n"

// conversationText is everything a client sent that a model will read, in
// order: the system prompt, every message of any role (a tool result included)
// and the arguments of every tool call an assistant turn carries. A client
// writes the history of an agent session itself, so no part of it is left out.
func conversationText(creq *adapter.CanonicalRequest) string {
	var parts []string
	add := func(s string) {
		if strings.TrimSpace(s) != "" {
			parts = append(parts, s)
		}
	}
	add(creq.System)
	for _, msg := range creq.Messages {
		add(msg.Content)
		for _, call := range msg.ToolCalls {
			add(call.Arguments)
		}
	}
	return strings.Join(parts, turnSeparator)
}
