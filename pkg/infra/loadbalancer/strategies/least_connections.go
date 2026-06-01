package strategies

import (
	"sync"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
)

type LeastConnections struct {
	mu       sync.Mutex
	backends []*backend.Backend
}

func NewLeastConnections(backends []*backend.Backend) *LeastConnections {
	return &LeastConnections{backends: backends}
}

func (lc *LeastConnections) Next(req *infracontext.RequestContext) *backend.Backend {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if len(lc.backends) == 0 {
		return nil
	}
	selected := lc.backends[0]
	lc.backends = append(lc.backends[1:], lc.backends[0])
	return selected
}

func (lc *LeastConnections) Name() string {
	return algorithm.LeastConnections
}
