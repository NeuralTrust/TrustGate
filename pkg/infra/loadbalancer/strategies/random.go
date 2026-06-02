package strategies

import (
	"crypto/rand"
	"math/big"
	"sync"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
	"github.com/google/uuid"
)

type Random struct {
	mu       sync.Mutex
	backends []*backend.Backend
}

func NewRandom(backends []*backend.Backend) *Random {
	return &Random{backends: backends}
}

func (r *Random) Next(req *infracontext.RequestContext, exclude map[uuid.UUID]struct{}) *backend.Backend {
	r.mu.Lock()
	defer r.mu.Unlock()
	candidates := filterExcluded(r.backends, exclude)
	if len(candidates) == 0 {
		return nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(candidates))))
	if err != nil {
		return candidates[0]
	}
	return candidates[n.Int64()]
}

func (r *Random) Name() string {
	return algorithm.Random
}
