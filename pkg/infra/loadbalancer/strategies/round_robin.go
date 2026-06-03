package strategies

import (
	"sync"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
)

type RoundRobin struct {
	mu         sync.Mutex
	registries []*registry.Registry
	current    int
}

func NewRoundRobin(registries []*registry.Registry) *RoundRobin {
	return &RoundRobin{registries: registries}
}

func (rr *RoundRobin) Next(req *infracontext.RequestContext, exclude map[ids.RegistryID]struct{}) *registry.Registry {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	n := len(rr.registries)
	if n == 0 {
		return nil
	}
	for i := 0; i < n; i++ {
		b := rr.registries[rr.current]
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
