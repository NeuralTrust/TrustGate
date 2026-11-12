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

package a2a

import (
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// ResolveAgent returns the enabled A2A registry of rc that name addresses: by
// id, or by name when exactly one of them has it.
func ResolveAgent(rc *appconsumer.RoutableConsumer, name string) (*registrydomain.Registry, bool) {
	var byName *registrydomain.Registry
	named := 0
	for _, reg := range rc.Registries {
		if !reg.Enabled || reg.Type != registrydomain.TypeA2A || reg.A2ATarget == nil {
			continue
		}
		if reg.ID.String() == name {
			return reg, true
		}
		if reg.Name == name {
			byName = reg
			named++
		}
	}
	return byName, named == 1
}
