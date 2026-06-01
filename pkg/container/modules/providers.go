package modules

import (
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/factory"
)

func Providers(c *container.Container) error {
	if err := c.Provide(adapter.NewRegistry); err != nil {
		return err
	}
	if err := c.Provide(factory.NewProviderLocator); err != nil {
		return err
	}
	return c.Invoke(func(cfg *config.Config) {
		providers.SetDefaultHTTPTimeout(cfg.Provider.RequestTimeout)
	})
}
