package loadbalancer

import (
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type Strategy interface {
	Next(req *types.RequestContext) *types.UpstreamTargetDTO
	Name() string
}

type Factory interface {
	CreateStrategy(upstream *types.UpstreamDTO) (Strategy, error)
}
