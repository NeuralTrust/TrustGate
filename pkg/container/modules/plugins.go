package modules

import (
	"log/slog"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/semantic"
	embeddingfactory "github.com/NeuralTrust/AgentGateway/pkg/infra/embedding/factory"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/plugins/cors"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/plugins/ratelimit"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/plugins/requestsize"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/plugins/semanticcache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/plugins/tokenratelimit"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"go.uber.org/dig"
)

type pluginParams struct {
	dig.In
	Cache    cache.Client
	Adapters *adapter.Registry
	Locator  embeddingfactory.EmbeddingServiceLocator
	Logger   *slog.Logger
}

func Plugins(c *container.Container) error {
	if err := c.Provide(newPluginRegistry); err != nil {
		return err
	}
	return c.Provide(func(reg appplugins.Registry, logger *slog.Logger) appplugins.Executor {
		return appplugins.NewExecutor(reg, logger)
	})
}

// newPluginRegistry builds the plugin catalog and registers every built-in
// plugin with its infrastructure dependencies.
func newPluginRegistry(p pluginParams) (appplugins.Registry, error) {
	reg := appplugins.NewRegistry()
	redisClient := p.Cache.RedisClient()
	store := semantic.NewRedisStore(redisClient, p.Logger)

	catalog := []appplugins.Plugin{
		ratelimit.New(redisClient),
		tokenratelimit.New(redisClient, p.Adapters),
		requestsize.New(),
		cors.New(),
		semanticcache.New(store, p.Locator, p.Adapters),
	}
	for _, plugin := range catalog {
		if err := reg.Register(plugin); err != nil {
			return nil, err
		}
	}
	return reg, nil
}
