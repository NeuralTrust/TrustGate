package modules

import "github.com/NeuralTrust/AgentGateway/pkg/container"

func All() []container.Option {
	return []container.Option{
		container.WithModule(Core),
		container.WithModule(API),
		container.WithModule(Cache),
		container.WithModule(CacheEvents),
		container.WithModule(Session),
		container.WithModule(Telemetry),
		container.WithModule(Auth),
		container.WithModule(Policy),
		container.WithModule(Plugins),
		container.WithModule(LoadBalancer),
		container.WithModule(Gateway),
		container.WithModule(Registry),
		container.WithModule(Role),
		container.WithModule(Consumer),
		container.WithModule(Catalog),
		container.WithModule(Providers),
		container.WithModule(Proxy),
		container.WithModule(ServerAdmin),
		container.WithModule(ServerProxy),
	}
}
