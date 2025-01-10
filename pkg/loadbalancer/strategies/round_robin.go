package strategies

import (
	"ai-gateway-ce/pkg/types"
	"sync"
)

// RoundRobin implements a simple round-robin load balancing strategy
type RoundRobin struct {
	mu      sync.Mutex
	targets []types.UpstreamTarget
	current int
}

func NewRoundRobin(targets []types.UpstreamTarget) *RoundRobin {
	return &RoundRobin{
		targets: targets,
	}
}

func (rr *RoundRobin) Next() *types.UpstreamTarget {
	rr.mu.Lock()
	defer rr.mu.Unlock()

	if len(rr.targets) == 0 {
		return nil
	}

	target := &rr.targets[rr.current]
	rr.current = (rr.current + 1) % len(rr.targets)
	return target
}

func (rr *RoundRobin) Name() string {
	return "round-robin"
}
