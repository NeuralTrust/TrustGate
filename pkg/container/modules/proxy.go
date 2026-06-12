package modules

import (
	proxyhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/proxy"
	appproxy "github.com/NeuralTrust/AgentGateway/pkg/app/proxy"
	approuting "github.com/NeuralTrust/AgentGateway/pkg/app/routing"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
)

func Proxy(c *container.Container) error {
	if err := c.Provide(approuting.NewResolver); err != nil {
		return err
	}
	if err := c.Provide(appproxy.NewProviderInvoker); err != nil {
		return err
	}
	if err := c.Provide(appproxy.NewForwarder); err != nil {
		return err
	}
	return c.Provide(proxyhttp.NewForwardedHandler)
}
