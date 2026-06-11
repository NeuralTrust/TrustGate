package modules

import (
	apihandler "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http"
	oauthhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/oauth"
	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/auth/introspection"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/auth/jwt"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/auth/mtls"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/auth/oidc"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/fingerprint"
	infraoauth "github.com/NeuralTrust/AgentGateway/pkg/infra/oauth"
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
	if err := c.Provide(func(
		apiKeys appauth.APIKeyFinder,
		credentials appauth.CredentialFinder,
		paths appconsumer.PathResolver,
	) middleware.IdentityResolver {
		return middleware.NewChainIdentityResolver(
			apiKeys,
			credentials,
			paths,
			oidc.NewValidator(nil),
			introspection.NewValidator(nil),
			mtls.NewValidator(),
		)
	}); err != nil {
		return err
	}
	if err := c.Provide(middleware.NewAuthMiddleware); err != nil {
		return err
	}
	if err := c.Provide(middleware.NewOAuthChallengeMiddleware); err != nil {
		return err
	}
	if err := c.Provide(func(credentials appauth.CredentialFinder, paths appconsumer.PathResolver) appoauth.MetadataService {
		return appoauth.NewMetadataService(credentials, paths, nil)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(cc cache.Client) appoauth.FlowStore {
		return infraoauth.NewStore(cc.RedisClient())
	}); err != nil {
		return err
	}
	if err := c.Provide(func(
		credentials appauth.CredentialFinder,
		paths appconsumer.PathResolver,
		store appoauth.FlowStore,
		connect appoauth.ConnectService,
	) appoauth.AuthProxy {
		return appoauth.NewAuthProxy(credentials, paths, nil, store, connect)
	}); err != nil {
		return err
	}
	if err := c.Provide(oauthhttp.NewProtectedResourceHandler); err != nil {
		return err
	}
	if err := c.Provide(oauthhttp.NewAuthorizationServerHandler); err != nil {
		return err
	}
	if err := c.Provide(oauthhttp.NewRegisterHandler); err != nil {
		return err
	}
	if err := c.Provide(oauthhttp.NewAuthorizeHandler); err != nil {
		return err
	}
	if err := c.Provide(oauthhttp.NewCallbackHandler); err != nil {
		return err
	}
	if err := c.Provide(oauthhttp.NewTokenHandler); err != nil {
		return err
	}
	if err := c.Provide(oauthhttp.NewConnectHandler); err != nil {
		return err
	}
	if err := c.Provide(oauthhttp.NewJWKSHandler); err != nil {
		return err
	}
	return nil
}
