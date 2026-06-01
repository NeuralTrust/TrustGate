package strategies

import (
	"sync"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
)

type RoundRobin struct {
	mu       sync.Mutex
	backends []*backend.Backend
	current  int
}

func NewRoundRobin(backends []*backend.Backend) *RoundRobin {
	return &RoundRobin{backends: backends}
}

func (rr *RoundRobin) Next(req *infracontext.RequestContext) *backend.Backend {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	if len(rr.backends) == 0 {
		return nil
	}
	b := rr.backends[rr.current]
	rr.current = (rr.current + 1) % len(rr.backends)
	return b
}

func (rr *RoundRobin) Name() string {
	return algorithm.RoundRobin
}
