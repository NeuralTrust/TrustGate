package strategies

import (
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type LeastConnections struct {
	mu      sync.Mutex
	targets []types.UpstreamTarget
}

func NewLeastConnections(targets []types.UpstreamTarget) *LeastConnections {
	return &LeastConnections{
		targets: targets,
	}
}

func (lc *LeastConnections) Next(req *types.RequestContext) *types.UpstreamTarget {
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
	return "least-connections"
}
