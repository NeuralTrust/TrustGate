package strategies

import (
	"crypto/rand"
	"math/big"
	"sync"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer/algorithm"
)

type Random struct {
	mu         sync.Mutex
	registries []*registry.Registry
}

func NewRandom(registries []*registry.Registry) *Random {
	return &Random{registries: registries}
}

func (r *Random) Next(req *infracontext.RequestContext, exclude map[ids.RegistryID]struct{}) *registry.Registry {
	r.mu.Lock()
	defer r.mu.Unlock()
	candidates := filterExcluded(r.registries, exclude)
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
