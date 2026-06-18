// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package modules

import (
	apihandler "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http"
	oauthhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/oauth"
	playgroundhttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/playground"
	"github.com/NeuralTrust/AgentGateway/pkg/api/middleware"
	"github.com/NeuralTrust/AgentGateway/pkg/api/resolver"
	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/AgentGateway/pkg/app/gateway"
	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	"github.com/NeuralTrust/AgentGateway/pkg/container"
	oidcauth "github.com/NeuralTrust/AgentGateway/pkg/infra/auth/oidc"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/auth/introspection"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/auth/jwt"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/auth/mtls"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/fingerprint"
	playgroundstore "github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/playground"
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
	if err := c.Provide(func(store *playgroundstore.Store) *playgroundhttp.GetTraceHandler {
		return playgroundhttp.NewGetTraceHandler(store)
	}); err != nil {
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
		verifier appauth.OIDCVerifier,
		cfg *config.Config,
	) middleware.IdentityResolver {
		return middleware.NewChainIdentityResolver(
			apiKeys,
			credentials,
			paths,
			oidcauth.NewOAuth2TokenValidator(verifier, nil),
			introspection.NewValidator(nil),
			mtls.NewValidator(),
			mtls.NewXFCCExtractor(),
			cfg.Server.TrustXFCCFrom,
		)
	}); err != nil {
		return err
	}
	if err := c.Provide(middleware.NewMCPAuthMiddleware); err != nil {
		return err
	}
	if err := c.Provide(oidcauth.NewVerifier); err != nil {
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
	if err := c.Provide(resolver.NewPlaygroundIdentityResolver); err != nil {
		return err
	}
	if err := c.Provide(resolver.NewOAuth2IdentityResolver); err != nil {
		return err
	}
	if err := c.Provide(resolver.NewOIDCIdentityResolver); err != nil {
		return err
	}
	if err := c.Provide(resolver.NewIdentityResolver); err != nil {
		return err
	}
	if err := c.Provide(middleware.NewAuthMiddleware); err != nil {
		return err
	}
	if err := c.Provide(middleware.NewOAuthChallengeMiddleware); err != nil {
		return err
	}
	if err := c.Provide(func(credentials appauth.CredentialFinder, paths appconsumer.PathResolver, store appoauth.FlowStore) appoauth.MetadataService {
		return appoauth.NewMetadataService(credentials, paths, nil, store)
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
