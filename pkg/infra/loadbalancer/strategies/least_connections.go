package strategies

import (
	"sync"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
)

type LeastConnections struct {
	mu         sync.Mutex
	registries []*registry.Registry
}

func NewLeastConnections(registries []*registry.Registry) *LeastConnections {
	return &LeastConnections{registries: registries}
}

func (lc *LeastConnections) Next(_ *infracontext.RequestContext, exclude map[ids.RegistryID]struct{}) *registry.Registry {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	n := len(lc.registries)
	if n == 0 {
		return nil
	}
	for i := 0; i < n; i++ {
		selected := lc.registries[0]
		lc.registries = append(lc.registries[1:], lc.registries[0])
		if !isExcluded(selected.ID, exclude) {
			return selected
		}
	}
	return nil
}

func (lc *LeastConnections) Name() string {
	return algorithm.LeastConnections
}
