package telemetry

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type Provider interface {
	Name() string
	ValidateConfig() error
	Handle(ctx context.Context, req *types.RequestContext, resp *types.ResponseContext) error
}
