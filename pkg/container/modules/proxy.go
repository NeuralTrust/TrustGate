package modules

import (
	proxyhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/proxy"
	appproxy "github.com/NeuralTrust/AgentGateway/pkg/app/proxy"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
)

func Proxy(c *container.Container) error {
	// TODO(providers): swap NewNotImplementedInvoker for the real LLM provider
	// invoker once the provider adapters (RUN-280) are ported.
	if err := c.Provide(appproxy.NewNotImplementedInvoker); err != nil {
		return err
	}
	if err := c.Provide(appproxy.NewForwarder); err != nil {
		return err
	}
	return c.Provide(proxyhttp.NewProxyHandler)
}
