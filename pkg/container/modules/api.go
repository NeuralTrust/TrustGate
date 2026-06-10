package modules

import (
	apihandler "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http"
	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	"github.com/NeuralTrust/AgentGateway/pkg/api/resolver"
	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	idpauth "github.com/NeuralTrust/AgentGateway/pkg/infra/auth/idp"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/auth/jwt"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/auth/oauthclient"
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
	if err := c.Provide(middleware.NewSessionMiddleware); err != nil {
		return err
	}
	if err := c.Provide(idpauth.NewVerifier); err != nil {
		return err
	}
	if err := c.Provide(func() appauth.OAuth2ClientTokenSource {
		return oauthclient.NewTokenSource(nil)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cfg *config.Config, finder appgateway.Finder) resolver.GatewayResolver {
		return resolver.NewGatewayResolver(finder, cfg.Server.GatewayDiscoveryMode, cfg.Server.GatewayBaseDomain)
	}); err != nil {
		return err
	}
	if err := c.Provide(resolver.NewAPIKeyIdentityResolver); err != nil {
		return err
	}
	if err := c.Provide(resolver.NewOAuth2IdentityResolver); err != nil {
		return err
	}
	if err := c.Provide(resolver.NewOAuth2ClientIdentityResolver); err != nil {
		return err
	}
	if err := c.Provide(resolver.NewIDPIdentityResolver); err != nil {
		return err
	}
	if err := c.Provide(resolver.NewIdentityResolver); err != nil {
		return err
	}
	if err := c.Provide(middleware.NewAuthMiddleware); err != nil {
		return err
	}
	return nil
}
