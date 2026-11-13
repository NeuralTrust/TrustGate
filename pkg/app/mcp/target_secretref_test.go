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
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestStaticTargetDropsReferences(t *testing.T) {
	t.Parallel()
	reg := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), MCPTarget: &registrydomain.MCPTarget{
		URL:     "https://mcp",
		Headers: map[string]string{"X-Ref": "secret://vault/ai/k", "X-Ok": "v"},
		Auth:    &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeStatic, Header: "Authorization", Value: "secret://vault/ai/token"},
	}}
	target := StaticTarget(reg)
	for k, v := range target.Headers {
		if strings.Contains(v, "secret://") {
			t.Fatalf("header %s carries a reference", k)
		}
	}
	if target.Headers["X-Ok"] != "v" || len(target.Headers) != 1 {
		t.Fatalf("headers = %v", target.Headers)
	}
}
