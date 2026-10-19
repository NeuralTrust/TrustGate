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

package store

import (
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func boundTarget(reg *registrydomain.Registry) *registrydomain.MCPTarget {
	if reg == nil {
		return nil
	}
	return reg.MCPTarget
}

func unpinnedURLVariables(vars []registrydomain.MCPURLVariable, bound *registrydomain.MCPTarget) []registrydomain.MCPURLVariable {
	if len(vars) == 0 {
		return nil
	}
	out := make([]registrydomain.MCPURLVariable, 0, len(vars))
	for _, v := range vars {
		if !bound.PinsURLVariable(v.Name) {
			out = append(out, v)
		}
	}
	return out
}

// withoutPinnedKeys returns config without the keys bound fixes. The map is
// returned unchanged when nothing is pinned, so a caller can compare it with
// the same rules as an exact config match.
func withoutPinnedKeys(config map[string]string, bound *registrydomain.MCPTarget) map[string]string {
	if len(config) == 0 || bound == nil {
		return config
	}
	out := make(map[string]string, len(config))
	for k, v := range config {
		if bound.PinsURLVariable(k) {
			continue
		}
		out[k] = v
	}
	if len(out) == len(config) {
		return config
	}
	return out
}

// sameInstanceIgnoringPins is SameInstance once keys bound pins are left out of
// both configs. A reinstall that no longer stores a pinned value is the row
// that still does.
func sameInstanceIgnoringPins(
	row *installationdomain.Installation,
	registryID, canonical ids.RegistryID,
	config map[string]string,
	bound *registrydomain.MCPTarget,
) bool {
	if row == nil {
		return false
	}
	view := *row
	view.Config = withoutPinnedKeys(row.Config, bound)
	return view.SameInstance(registryID, canonical, withoutPinnedKeys(config, bound))
}

// sameConfigIgnoringPins is SameConfig once keys bound pins are left out of
// both configs.
func sameConfigIgnoringPins(row *installationdomain.Installation, config map[string]string, bound *registrydomain.MCPTarget) bool {
	if row == nil {
		return len(withoutPinnedKeys(config, bound)) == 0
	}
	view := *row
	view.Config = withoutPinnedKeys(row.Config, bound)
	return view.SameConfig(withoutPinnedKeys(config, bound))
}

func servingRegistry(regs []*registrydomain.Registry, registryID ids.RegistryID) *registrydomain.Registry {
	if !registryID.IsNil() {
		return pickRegistry(regs, registryID)
	}
	if len(regs) == 0 {
		return nil
	}
	return regs[0]
}
