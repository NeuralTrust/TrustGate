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

package strategies

import (
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

func isExcluded(id ids.RegistryID, exclude map[ids.RegistryID]struct{}) bool {
	if len(exclude) == 0 {
		return false
	}
	_, ok := exclude[id]
	return ok
}

func filterExcluded(registries []*registry.Registry, exclude map[ids.RegistryID]struct{}) []*registry.Registry {
	if len(exclude) == 0 {
		return registries
	}
	out := make([]*registry.Registry, 0, len(registries))
	for _, b := range registries {
		if !isExcluded(b.ID, exclude) {
			out = append(out, b)
		}
	}
	return out
}
