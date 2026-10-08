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

package registry

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestStoreCode(t *testing.T) {
	id := ids.New[ids.RegistryKind]()
	code := CustomStoreCode(id)
	if got, ok := ParseCustomStoreCode(code); !ok || got != id {
		t.Fatalf("a custom code round-trips, got %v %v", got, ok)
	}
	for _, other := range []string{"", "github", "custom:", "custom:not-a-uuid", "custom:" + ids.RegistryID{}.String(), "com.asana/mcp"} {
		if _, ok := ParseCustomStoreCode(other); ok {
			t.Fatalf("%q is no custom code", other)
		}
	}
	cases := map[string]struct {
		reg  *Registry
		want string
	}{
		"catalog server": {&Registry{ID: id, MCPTarget: &MCPTarget{Code: "github"}}, "github"},
		"custom server":  {&Registry{ID: id, MCPTarget: &MCPTarget{URL: "https://mcp.acme"}}, code},
		"not MCP":        {&Registry{ID: id}, ""},
		"nil":            {nil, ""},
	}
	for name, tc := range cases {
		if got := StoreCode(tc.reg); got != tc.want {
			t.Fatalf("%s: StoreCode = %q, want %q", name, got, tc.want)
		}
	}
}
