package modules

import (
	apihandler "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http"
	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
)

func API(c *container.Container) error {
	if err := c.Provide(apihandler.NewHealthHandler); err != nil {
		return err
	}
	if err := c.Provide(apihandler.NewVersionHandler); err != nil {
		return err
	}
	if err := c.Provide(middleware.NewRequestIDMiddleware); err != nil {
		return err
	}
	if err := c.Provide(middleware.NewPanicRecoverMiddleware); err != nil {
		return err
	}
	if err := c.Provide(middleware.NewAccessLogMiddleware); err != nil {
		return err
	}
	if err := c.Provide(middleware.NewCORSMiddleware); err != nil {
		return err
	}
	if err := c.Provide(middleware.NewSecurityHeadersMiddleware); err != nil {
		return err
	}
	return nil
}
