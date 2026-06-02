package strategies

import (
	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/google/uuid"
)

func isExcluded(id uuid.UUID, exclude map[uuid.UUID]struct{}) bool {
	if len(exclude) == 0 {
		return false
	}
	_, ok := exclude[id]
	return ok
}

func filterExcluded(backends []*backend.Backend, exclude map[uuid.UUID]struct{}) []*backend.Backend {
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
