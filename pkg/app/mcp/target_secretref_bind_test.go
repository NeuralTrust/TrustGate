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
	"errors"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestRevisionFollowsTheSecretFingerprint(t *testing.T) {
	t.Parallel()
	reg := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), MCPTarget: &registrydomain.MCPTarget{URL: "https://mcp"}}
	plain := StaticTarget(reg).Revision
	if strings.Contains(plain, ":s:") {
		t.Fatalf("literal revision changed: %q", plain)
	}
	reg.BindSecrets(&registrydomain.Registry{}, "d1")
	r1 := StaticTarget(reg).Revision
	reg.BindSecrets(&registrydomain.Registry{}, "d2")
	if r1 == StaticTarget(reg).Revision || !strings.HasPrefix(r1, plain) {
		t.Fatalf("revisions %q / %q", r1, StaticTarget(reg).Revision)
	}
}

func TestMarkedRegistryIsNotDialed(t *testing.T) {
	t.Parallel()
	reg := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), MCPTarget: &registrydomain.MCPTarget{URL: "https://mcp"}}
	reg.MarkCredentialUnavailable()
	if _, err := (&composer{}).target(context.Background(), nil, reg); !errors.Is(err, registrydomain.ErrSecretUnavailable) {
		t.Fatalf("target: %v", err)
	}
}
