package telemetry

import (
	"errors"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	"github.com/NeuralTrust/TrustGate/pkg/infra/telemetry/trustlens"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/mitchellh/mapstructure"
)

type ProvidersDI struct {
	Breaker httpx.CircuitBreaker
	Client  httpx.Client
}

func NewProvider(p types.ProviderConfig, di ProvidersDI) (domain.Provider, error) {
	switch p.Name {
	case trustlens.ProviderName:
		var cfg trustlens.Config
		if err := mapstructure.Decode(p.Settings, &cfg); err != nil {
			return nil, err
		}
		return trustlens.NewTrustLensProvider(cfg, di.Breaker, di.Client), nil
	default:
		return nil, errors.New("unknown provider: " + p.Name)
	}
}
