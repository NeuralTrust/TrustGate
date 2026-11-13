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

package auth

import (
	"context"
	"log/slog"

	appsecretref "github.com/NeuralTrust/TrustGate/pkg/app/secretref"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

//go:generate mockery --name=CredentialFinder --dir=. --output=./mocks --filename=auth_credential_finder_mock.go --case=underscore --with-expecter
type CredentialFinder interface {
	OAuth2Auths(ctx context.Context) ([]*domain.Auth, error)
	OAuth2AuthsForGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*domain.Auth, error)
	MTLSAuths(ctx context.Context) ([]*domain.Auth, error)
	// DefaultOAuth2ForGateway returns the built-in NeuralTrust identity
	// provider scoped to the given gateway (a copy carrying that GatewayID), or
	// nil when the default IdP is not configured. It is used as the fallback
	// when an MCP consumer has no oauth2 identity provider of its own.
	DefaultOAuth2ForGateway(gatewayID ids.GatewayID) *domain.Auth
}

var _ CredentialFinder = (*credentialFinder)(nil)

const (
	oauth2CacheKey           = "enabled:oauth2"
	oauth2GatewayCachePrefix = "enabled:oauth2:gw:"
	mtlsCacheKey             = "enabled:mtls"
)

type credentialFinder struct {
	repo       domain.Repository
	cache      *cache.TTLMap
	logger     *slog.Logger
	defaultIdP *domain.Auth
	secrets    appsecretref.ValuesResolver
}

// CredentialFinderOption tunes NewCredentialFinder.
type CredentialFinderOption func(*credentialFinder)

// WithSecretValues resolves the secret references of the identity providers
// the finder returns, on a plane that loads a store file.
func WithSecretValues(r appsecretref.ValuesResolver) CredentialFinderOption {
	return func(f *credentialFinder) { f.secrets = r }
}

func NewCredentialFinder(repo domain.Repository, manager *cache.TTLMapManager, logger *slog.Logger, defaultIdP *domain.Auth, opts ...CredentialFinderOption) CredentialFinder {
	f := &credentialFinder{
		repo:       repo,
		cache:      manager.GetTTLMap(cache.AuthTTLName),
		logger:     logger,
		defaultIdP: defaultIdP,
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// resolve replaces the secret references of auths, grouped by gateway, so
// what is cached and returned never carries one.
func (f *credentialFinder) resolve(ctx context.Context, auths []*domain.Auth) []*domain.Auth {
	if f.secrets == nil || len(auths) == 0 {
		return auths
	}
	byGateway := map[ids.GatewayID][]int{}
	for i, a := range auths {
		if a != nil && len(appsecretref.AuthRefs(a).Uses) > 0 {
			byGateway[a.GatewayID] = append(byGateway[a.GatewayID], i)
		}
	}
	if len(byGateway) == 0 {
		return auths
	}
	out := append([]*domain.Auth(nil), auths...)
	for gw, indexes := range byGateway {
		group := make([]*domain.Auth, len(indexes))
		for j, i := range indexes {
			group[j] = auths[i]
		}
		resolved := appsecretref.GatewayAuths(ctx, f.secrets, gw, appsecretref.SourceAuthCredentials, group)
		for j, i := range indexes {
			out[i] = resolved[j]
		}
	}
	return out
}

// OAuth2Auths returns every enabled oauth2 auth, plus the built-in NeuralTrust
// identity provider when configured. The default is appended to a copy of the
// cached slice so the synthetic entry is never written into the cache and the
// cached slice is never aliased by callers.
func (f *credentialFinder) OAuth2Auths(ctx context.Context) ([]*domain.Auth, error) {
	auths, err := f.findByType(ctx, oauth2CacheKey, domain.TypeOAuth2)
	if err != nil {
		return nil, err
	}
	if f.defaultIdP == nil {
		return auths, nil
	}
	out := make([]*domain.Auth, 0, len(auths))
	out = append(out, auths...)
	out = append(out, f.defaultIdP)
	return out, nil
}

// DefaultOAuth2ForGateway returns the built-in NeuralTrust identity provider
// bound to the given gateway, or nil when it is not configured. The default is
// platform-wide, so its owning gateway is resolved per request from the
// addressed MCP consumer.
func (f *credentialFinder) DefaultOAuth2ForGateway(gatewayID ids.GatewayID) *domain.Auth {
	if f.defaultIdP == nil {
		return nil
	}
	clone := *f.defaultIdP
	clone.GatewayID = gatewayID
	return &clone
}

func (f *credentialFinder) OAuth2AuthsForGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*domain.Auth, error) {
	key := oauth2GatewayCachePrefix + gatewayID.String()
	if cached, ok := f.cache.Get(key); ok {
		if auths, ok := cached.([]*domain.Auth); ok {
			return auths, nil
		}
		f.logger.Warn("credential cache entry failed type assertion; falling back to database")
		f.cache.Delete(key)
	}
	auths, err := f.repo.ListEnabledByGatewayAndType(ctx, gatewayID, domain.TypeOAuth2)
	if err != nil {
		return nil, err
	}
	auths = f.resolve(ctx, auths)
	f.cache.Set(key, auths)
	return auths, nil
}

func (f *credentialFinder) MTLSAuths(ctx context.Context) ([]*domain.Auth, error) {
	return f.findByType(ctx, mtlsCacheKey, domain.TypeMTLS)
}

func (f *credentialFinder) findByType(ctx context.Context, key string, t domain.Type) ([]*domain.Auth, error) {
	if cached, ok := f.cache.Get(key); ok {
		if auths, ok := cached.([]*domain.Auth); ok {
			return auths, nil
		}
		f.logger.Warn("credential cache entry failed type assertion; falling back to database")
		f.cache.Delete(key)
	}
	auths, err := f.repo.FindEnabledByTypes(ctx, []domain.Type{t})
	if err != nil {
		return nil, err
	}
	auths = f.resolve(ctx, auths)
	f.cache.Set(key, auths)
	return auths, nil
}
