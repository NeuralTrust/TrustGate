package strategies

import (
	"sync"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
)

type RoundRobin struct {
	mu      sync.Mutex
	targets []backend.Target
	current int
}

func NewRoundRobin(targets []backend.Target) *RoundRobin {
	return &RoundRobin{targets: targets}
}

func (rr *RoundRobin) Next(req *infracontext.RequestContext) *backend.Target {
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
	return algorithm.RoundRobin
}
