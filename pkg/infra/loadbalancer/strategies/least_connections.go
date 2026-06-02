package strategies

import (
	"sync"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
	"github.com/google/uuid"
)

type LeastConnections struct {
	mu       sync.Mutex
	backends []*backend.Backend
}

func NewLeastConnections(backends []*backend.Backend) *LeastConnections {
	return &LeastConnections{backends: backends}
}

func (lc *LeastConnections) Next(req *infracontext.RequestContext, exclude map[uuid.UUID]struct{}) *backend.Backend {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	n := len(lc.backends)
	if n == 0 {
		return nil
	}
	for i := 0; i < n; i++ {
		selected := lc.backends[0]
		lc.backends = append(lc.backends[1:], lc.backends[0])
		if !isExcluded(selected.ID, exclude) {
			return selected
		}
	}
	return nil
}

func (lc *LeastConnections) Name() string {
	return algorithm.LeastConnections
}
