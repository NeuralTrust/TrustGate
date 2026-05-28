package modules

import (
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/embedding"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/loadbalancer"
	"go.uber.org/dig"
)

type loadBalancerParams struct {
	dig.In
	EmbeddingRepo  embedding.Repository            `optional:"true"`
	ServiceLocator factory.EmbeddingServiceLocator `optional:"true"`
}

func LoadBalancer(c *container.Container) error {
	if err := c.Provide(func() factory.EmbeddingServiceLocator {
		return factory.NewServiceLocator(nil)
	}); err != nil {
		return err
	}
	return c.Provide(func(p loadBalancerParams) loadbalancer.Factory {
		return loadbalancer.NewBaseFactory(p.EmbeddingRepo, p.ServiceLocator)
	})
}
