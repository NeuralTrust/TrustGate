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

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

//go:generate mockery --name=CredentialFinder --dir=. --output=./mocks --filename=auth_credential_finder_mock.go --case=underscore --with-expecter
type CredentialFinder interface {
	OAuth2Auths(ctx context.Context) ([]*domain.Auth, error)
	OAuth2AuthsForGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*domain.Auth, error)
	MTLSAuths(ctx context.Context) ([]*domain.Auth, error)
}

var _ CredentialFinder = (*credentialFinder)(nil)

const (
	oauth2CacheKey           = "enabled:oauth2"
	oauth2GatewayCachePrefix = "enabled:oauth2:gw:"
	mtlsCacheKey             = "enabled:mtls"
)

type credentialFinder struct {
	repo   domain.Repository
	cache  *cache.TTLMap
	logger *slog.Logger
}

func NewCredentialFinder(repo domain.Repository, manager *cache.TTLMapManager, logger *slog.Logger) CredentialFinder {
	return &credentialFinder{
		repo:   repo,
		cache:  manager.GetTTLMap(cache.AuthTTLName),
		logger: logger,
	}
}

func (f *credentialFinder) OAuth2Auths(ctx context.Context) ([]*domain.Auth, error) {
	return f.findByType(ctx, oauth2CacheKey, domain.TypeOAuth2)
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
	f.cache.Set(key, auths)
	return auths, nil
}
