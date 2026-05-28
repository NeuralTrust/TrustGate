package strategies

import (
	"crypto/rand"
	"math/big"
	"sync"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
)

type Random struct {
	mu      sync.Mutex
	targets []backend.Target
}

func NewRandom(targets []backend.Target) *Random {
	return &Random{targets: targets}
}

func (r *Random) Next(req *infracontext.RequestContext) *backend.Target {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.targets) == 0 {
		return nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(r.targets))))
	if err != nil {
		return &r.targets[0]
	}
	return &r.targets[n.Int64()]
}

func (r *Random) Name() string {
	return algorithm.Random
}
