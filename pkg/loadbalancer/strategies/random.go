package strategies

import (
	"crypto/rand"
	"math/big"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type Random struct {
	mu      sync.Mutex
	targets []types.UpstreamTarget
}

func NewRandom(targets []types.UpstreamTarget) *Random {
	return &Random{
		targets: targets,
	}
}

func (r *Random) Next(req *types.RequestContext) *types.UpstreamTarget {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.targets) == 0 {
		return nil
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(r.targets))))
	if err != nil {
		return &r.targets[0] // fallback to first target on error
	}
	return &r.targets[n.Int64()]
}

func (r *Random) Name() string {
	return "random"
}
