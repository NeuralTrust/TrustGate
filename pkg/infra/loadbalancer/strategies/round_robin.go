package strategies

import (
	"sync"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
	"github.com/google/uuid"
)

type RoundRobin struct {
	mu       sync.Mutex
	backends []*backend.Backend
	current  int
}

func NewRoundRobin(backends []*backend.Backend) *RoundRobin {
	return &RoundRobin{backends: backends}
}

func (rr *RoundRobin) Next(req *infracontext.RequestContext, exclude map[uuid.UUID]struct{}) *backend.Backend {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	n := len(rr.backends)
	if n == 0 {
		return nil
	}
	for i := 0; i < n; i++ {
		b := rr.backends[rr.current]
		rr.current = (rr.current + 1) % n
		if !isExcluded(b.ID, exclude) {
			return b
		}
	}
	return nil
}

func (rr *RoundRobin) Name() string {
	return algorithm.RoundRobin
}
