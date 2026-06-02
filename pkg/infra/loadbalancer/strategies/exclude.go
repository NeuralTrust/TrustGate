package strategies

import (
	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

func isExcluded(id ids.BackendID, exclude map[ids.BackendID]struct{}) bool {
	if len(exclude) == 0 {
		return false
	}
	_, ok := exclude[id]
	return ok
}

func filterExcluded(backends []*backend.Backend, exclude map[ids.BackendID]struct{}) []*backend.Backend {
	if len(exclude) == 0 {
		return backends
	}
	out := make([]*backend.Backend, 0, len(backends))
	for _, b := range backends {
		if !isExcluded(b.ID, exclude) {
			out = append(out, b)
		}
	}
	return out
}
