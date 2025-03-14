package strategies

import (
	"context"
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

func (lc *LeastConnections) Next(ctx context.Context) *types.UpstreamTarget {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if len(lc.targets) == 0 {
		return nil
	}

	// For now, just do round-robin since connection tracking is handled at LoadBalancer level
	selected := &lc.targets[0]
	lc.targets = append(lc.targets[1:], lc.targets[0])
	return selected
}

func (lc *LeastConnections) Name() string {
	return "least-connections"
}
