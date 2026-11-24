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

package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestMCPRequestAttrsNameTheCalledAgent(t *testing.T) {
	t.Parallel()
	operation, tool, _, _ := mcpRequestAttrs("tools/call", json.RawMessage(`{"name":"trustgate_call_agent","arguments":{"agent":"Travel planner","message":"hi"}}`))
	if operation != "tool" || tool != "Travel planner" {
		t.Fatalf("operation %q tool %q, want the agent", operation, tool)
	}
	_, tool, _, _ = mcpRequestAttrs("tools/call", json.RawMessage(`{"name":"trustgate_list_agents"}`))
	if tool != appmcp.ListAgentsToolName {
		t.Fatalf("tool %q, want the listing itself", tool)
	}
}

func TestStoreInstructionsMentionTheAgentTools(t *testing.T) {
	t.Parallel()
	store := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(ids.New[ids.GatewayKind]())}
	instructions := serverInstructions(store)
	for _, want := range []string{`{"kind": "agent"}`, `{"agent": <id>, "message": …}`, "context_id"} {
		if !strings.Contains(instructions, want) {
			t.Fatalf("Store instructions %q do not mention %s", instructions, want)
		}
	}
	app := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind](), Type: consumerdomain.TypeMCP}}
	for _, unwanted := range []string{`"kind": "agent"`, appmcp.CallAgentToolName, appmcp.ListAgentsToolName} {
		if strings.Contains(serverInstructions(app), unwanted) {
			t.Fatalf("an application's instructions do not mention the agent tools (%s)", unwanted)
		}
	}
}
