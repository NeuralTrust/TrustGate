package modules

import (
	apihandler "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http"
	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/auth/jwt"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/fingerprint"
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
	if err := c.Provide(middleware.NewMetricsMiddleware); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config) jwt.Manager {
		return jwt.NewJwtManager(&cfg.Server)
	}); err != nil {
		return err
	}
	if err := c.Provide(middleware.NewAdminAuthMiddleware); err != nil {
		return err
	}
	if err := c.Provide(fingerprint.NewFingerPrintTracker); err != nil {
		return err
	}
	if err := c.Provide(middleware.NewFingerPrintMiddleware); err != nil {
		return err
	}
	if err := c.Provide(middleware.NewSessionMiddleware); err != nil {
		return err
	}
	if err := c.Provide(middleware.NewAPIKeyIdentityResolver); err != nil {
		return err
	}
	if err := c.Provide(middleware.NewAuthMiddleware); err != nil {
		return err
	}
	return nil
}
