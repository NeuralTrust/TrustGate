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
