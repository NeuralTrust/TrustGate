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
	mu       sync.Mutex
	backends []*backend.Backend
}

func NewRandom(backends []*backend.Backend) *Random {
	return &Random{backends: backends}
}

func (r *Random) Next(req *infracontext.RequestContext) *backend.Backend {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.backends) == 0 {
		return nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(r.backends))))
	if err != nil {
		return r.backends[0]
	}
	return r.backends[n.Int64()]
}

func (r *Random) Name() string {
	return algorithm.Random
}
