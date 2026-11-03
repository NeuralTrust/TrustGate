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
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func TestExecuteMCPCarriesMCPServer(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		id   string
		code string
		want *GuardMCPServer
	}{
		{name: "catalog registry", id: "reg-1", code: "com.asana/mcp", want: &GuardMCPServer{ID: "reg-1", Code: "com.asana/mcp"}},
		{name: "custom registry", id: "reg-2", want: &GuardMCPServer{ID: "reg-2"}},
		{name: "no registry", want: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
			p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
			req := mcpRequestContext()
			req.MCPServerID = tc.id
			req.MCPServerCode = tc.code

			if _, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil)); err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if f.count() != 1 {
				t.Fatalf("evaluate calls = %d, want 1", f.count())
			}
			got := f.captured().Attributes.MCPServer
			if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
				t.Fatalf("mcp_server = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestExecuteLLMOmitsMCPServer(t *testing.T) {
	t.Parallel()
	f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	req := chatRequestOf(t, "hello")
	req.MCPServerID = "reg-1"

	if _, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil)); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if f.count() != 1 {
		t.Fatalf("evaluate calls = %d, want 1", f.count())
	}
	if got := f.captured().Attributes.MCPServer; got != nil {
		t.Fatalf("mcp_server = %+v, want none on an LLM request", got)
	}
}
