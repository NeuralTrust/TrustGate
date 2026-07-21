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
	apihandler "github.com/NeuralTrust/TrustGate/pkg/api/handler/http"
	oauthhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/oauth"
	playgroundhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/playground"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/app/identity/sts"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/introspection"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/mtls"
	oidcauth "github.com/NeuralTrust/TrustGate/pkg/infra/auth/oidc"
	authsession "github.com/NeuralTrust/TrustGate/pkg/infra/auth/session"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	playgroundstore "github.com/NeuralTrust/TrustGate/pkg/infra/metrics/playground"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"go.uber.org/dig"
)

type healthParams struct {
	dig.In
	Store configsync.ConfigStore[*readmodel.Snapshot] `optional:"true"`
}

func API(c *container.Container) error {
	if err := c.Provide(func(p healthParams) *apihandler.HealthHandler {
		var checks []apihandler.ReadinessCheck
		if p.Store != nil {
			checks = append(checks, apihandler.ReadinessCheck{Name: "snapshot", Ping: configsync.ReadinessCheck(p.Store)})
		}
		return apihandler.NewHealthHandler(checks...)
	}); err != nil {
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
	if err := c.Provide(middleware.NewMCPMetricsMiddleware); err != nil {
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
	if err := c.Provide(middleware.NewSessionMiddleware); err != nil {
		return err
	}
	if err := c.Provide(func(signer sts.TokenSigner) (appauth.SessionTokenVerifier, error) {
		return authsession.NewVerifier(signer)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(
		apiKeys appauth.APIKeyFinder,
		credentials appauth.CredentialFinder,
		paths appconsumer.PathResolver,
		verifier appauth.OIDCVerifier,
		sessionVerifier appauth.SessionTokenVerifier,
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
			sessionVerifier,
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
		return resolver.NewGatewayResolver(finder, cfg.Server.GatewayBaseDomain)
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
	if err := c.Provide(func() appoauth.UserInfoClient {
		return infraoauth.NewUserInfoClient(nil)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(
		credentials appauth.CredentialFinder,
		paths appconsumer.PathResolver,
		store appoauth.FlowStore,
		connect appoauth.ConnectService,
		signer sts.TokenSigner,
		userinfo appoauth.UserInfoClient,
	) appoauth.AuthProxy {
		return appoauth.NewAuthProxy(credentials, paths, nil, store, connect, signer, userinfo)
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
	if err := c.Provide(func(proxy appoauth.AuthProxy, finder appgateway.Finder, cfg *config.Config) *oauthhttp.AuthorizeHandler {
		gateways := resolver.NewGatewayResolver(finder, cfg.Server.MCPBaseDomain)
		return oauthhttp.NewAuthorizeHandler(proxy, gateways)
	}); err != nil {
		return err
	}
	if err := c.Provide(oauthhttp.NewCallbackHandler); err != nil {
		return err
	}
	if err := c.Provide(func(proxy appoauth.AuthProxy, finder appgateway.Finder, cfg *config.Config) *oauthhttp.TokenHandler {
		gateways := resolver.NewGatewayResolver(finder, cfg.Server.MCPBaseDomain)
		return oauthhttp.NewTokenHandler(proxy, gateways)
	}); err != nil {
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
