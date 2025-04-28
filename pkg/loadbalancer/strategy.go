package loadbalancer

import (
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type Strategy interface {
	Next(req *types.RequestContext) *types.UpstreamTarget
	Name() string
}

type Factory interface {
	CreateStrategy(upstream *types.Upstream) (Strategy, error)
}
