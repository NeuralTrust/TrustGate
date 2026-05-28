package strategies

import (
	"sync"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
)

type LeastConnections struct {
	mu      sync.Mutex
	targets []backend.Target
}

func NewLeastConnections(targets []backend.Target) *LeastConnections {
	return &LeastConnections{targets: targets}
}

func (lc *LeastConnections) Next(req *infracontext.RequestContext) *backend.Target {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if len(lc.targets) == 0 {
		return nil
	}
	selected := &lc.targets[0]
	lc.targets = append(lc.targets[1:], lc.targets[0])
	return selected
}

func (lc *LeastConnections) Name() string {
	return algorithm.LeastConnections
}
