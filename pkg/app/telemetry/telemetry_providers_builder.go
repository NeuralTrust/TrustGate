package telemetry

import (
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	factory "github.com/NeuralTrust/TrustGate/pkg/infra/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

type ProvidersBuilder interface {
	Build(configs []types.ProviderConfig) ([]domain.Provider, error)
}

type providersBuilder struct {
	breaker httpx.CircuitBreaker
	client  httpx.Client
}

func NewTelemetryProvidersBuilder(breaker httpx.CircuitBreaker, client httpx.Client) ProvidersBuilder {
	return &providersBuilder{
		breaker: breaker,
		client:  client,
	}
}

func (v *providersBuilder) Build(configs []types.ProviderConfig) ([]domain.Provider, error) {
	var providers []domain.Provider
	for _, config := range configs {
		telemetryProvider, err := factory.NewProvider(config, factory.ProvidersDI{
			Breaker: v.breaker,
			Client:  v.client,
		})
		if err != nil {
			return nil, err
		}
		err = telemetryProvider.ValidateConfig()
		if err != nil {
			return nil, err
		}
		providers = append(providers, telemetryProvider)
	}
	return providers, nil
}
