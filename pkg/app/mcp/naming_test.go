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
	"context"
	"testing"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func namedFor(reg *registrydomain.Registry, name string) string {
	return resolveExposedNames([]exposedName{exposedNameFor(name, reg)}, true)[0]
}

func TestResolveExposedNames_PerInstanceIsAlwaysPrefixed(t *testing.T) {
	t.Parallel()
	got := resolveExposedNames([]exposedName{
		{name: "query", registryID: "11111111-1111-1111-1111-111111111111", perInstance: true},
		{name: "query", registryID: "22222222-2222-2222-2222-222222222222"},
	}, true)
	want := []string{"mcp_bafde89c041e1756_query_a8b771920b8319e4", "mcp_05d17100b346c29d_query_a8b771920b8319e4"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("names = %v, want %v", got, want)
	}
	solo := resolveExposedNames([]exposedName{
		{name: "query", registryID: "1", perInstance: true},
		{name: "search", registryID: "2"},
	}, false)
	if solo[0] != "mcp_6b86b273ff34fce1_query_a8b771920b8319e4" || solo[1] != "search" {
		t.Fatalf("names = %v, want isolated instance query and raw search", solo)
	}
}

func perInstanceRegistry(t *testing.T, name, url string, cfg map[string]string) *registrydomain.Registry {
	t.Helper()
	reg := mcpRegistry(t, name, url)
	reg.MCPTarget.Code = "snowflake"
	reg.MCPTarget.InstanceConfig = cfg
	return reg
}

// Two instances of one catalog code expose their tools under a per-instance
// prefix. When one instance is unreachable the survivor keeps its prefix — the
// name a client cached must not flap with the sibling's availability.
func TestComposer_ListTools_PerInstanceNamesDoNotFlap(t *testing.T) {
	t.Parallel()
	finance := perInstanceRegistry(t, "Snowflake (FINANCE)", "https://a.example.com/mcp", map[string]string{"schema": "FINANCE"})
	analytics := perInstanceRegistry(t, "Snowflake (ANALYTICS)", "https://b.example.com/mcp", map[string]string{"schema": "ANALYTICS"})
	consumer := &consumerdomain.Consumer{Type: consumerdomain.TypeMCP, MCP: &consumerdomain.MCPPolicy{FailMode: consumerdomain.FailModeOpen}}

	bothUp := newTestComposer(&fakeDialer{upstreams: map[string]*fakeUpstream{
		"https://a.example.com/mcp": {tools: tools("query")},
		"https://b.example.com/mcp": {tools: tools("query")},
	}})
	got, err := bothUp.ListTools(context.Background(), routable(consumer, finance, analytics))
	if err != nil {
		t.Fatalf("both up: %v", err)
	}
	if names := toolNames(got); len(names) != 2 || names[0] != namedFor(finance, "query") || names[1] != namedFor(analytics, "query") {
		t.Fatalf("both up: tools = %v, want [%s %s]", names, namedFor(finance, "query"), namedFor(analytics, "query"))
	}

	oneDown := newTestComposer(&fakeDialer{
		upstreams: map[string]*fakeUpstream{"https://a.example.com/mcp": {tools: tools("query")}},
		dialErr:   map[string]error{"https://b.example.com/mcp": ErrUnreachable},
	})
	got, err = oneDown.ListTools(context.Background(), routable(consumer, finance, analytics))
	if err != nil {
		t.Fatalf("one down: %v", err)
	}
	if names := toolNames(got); len(names) != 1 || names[0] != namedFor(finance, "query") {
		t.Fatalf("one down: tools = %v, want [%s]", names, namedFor(finance, "query"))
	}

	// And the prefixed name is callable, so a client that cached it keeps working.
	if _, err := oneDown.CallTool(context.Background(), routable(consumer, finance, analytics), namedFor(finance, "query"), nil); err != nil {
		t.Fatalf("calling the stable per-instance name: %v", err)
	}
}
