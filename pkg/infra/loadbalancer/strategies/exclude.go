package strategies

import (
	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	"github.com/google/uuid"
)

// isExcluded reports whether a backend id is in the per-request exclude set
// (backends already attempted in this request, to avoid re-selecting them).
func isExcluded(id uuid.UUID, exclude map[uuid.UUID]struct{}) bool {
	if len(exclude) == 0 {
		return false
	}
	_, ok := exclude[id]
	return ok
}

// filterExcluded returns the backends not present in the exclude set, sharing
// the input slice when nothing is excluded.
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
