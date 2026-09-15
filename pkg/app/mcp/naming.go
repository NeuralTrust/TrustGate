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
	"crypto/sha256"
	"encoding/hex"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func resolveNames(candidates []binding, registries []*registrydomain.Registry) []binding {
	items := make([]exposedName, len(candidates))
	for i, b := range candidates {
		items[i] = exposedNameFor(b.exposed, b.registry)
	}
	out := make([]binding, 0, len(candidates))
	for i, name := range resolveExposedNames(items, len(registries) > 1) {
		b := candidates[i]
		b.exposed = name
		out = append(out, b)
	}
	return out
}

type exposedName struct {
	name        string
	registryID  string
	perInstance bool
}

func exposedNameFor(name string, reg *registrydomain.Registry) exposedName {
	it := exposedName{name: name, registryID: reg.ID.String()}
	if reg.MCPTarget != nil && len(reg.MCPTarget.InstanceConfig) > 0 {
		it.perInstance = true
	}
	return it
}

func resolveExposedNames(items []exposedName, federated bool) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.name
		if federated || it.perInstance {
			sum := sha256.Sum256([]byte(it.registryID))
			name := it.name
			digest := sha256.Sum256([]byte(name))
			if len(name) > 26 {
				name = name[:26]
			}
			out[i] = "mcp_" + hex.EncodeToString(sum[:8]) + "_" + name + "_" + hex.EncodeToString(digest[:8])
		}
	}
	return out
}
