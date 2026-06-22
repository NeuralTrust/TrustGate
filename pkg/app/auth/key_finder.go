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
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

//go:generate mockery --name=APIKeyFinder --dir=. --output=./mocks --filename=auth_api_key_finder_mock.go --case=underscore --with-expecter
type APIKeyFinder interface {
	FindByAPIKey(ctx context.Context, rawKey string) (*domain.Auth, error)
}

var _ APIKeyFinder = (*apiKeyFinder)(nil)

type apiKeyFinder struct {
	repo     domain.Repository
	keyCache *cache.TTLMap
	logger   *slog.Logger
}

func NewAPIKeyFinder(repo domain.Repository, manager *cache.TTLMapManager, logger *slog.Logger) APIKeyFinder {
	return &apiKeyFinder{
		repo:     repo,
		keyCache: manager.GetTTLMap(cache.AuthKeyTTLName),
		logger:   logger,
	}
}

func (f *apiKeyFinder) FindByAPIKey(ctx context.Context, rawKey string) (*domain.Auth, error) {
	hash := domain.HashAPIKey(rawKey)
	if cached, ok := f.keyCache.Get(hash); ok {
		if a, ok := cached.(*domain.Auth); ok {
			return a, nil
		}
		f.logger.Warn("auth-key cache entry failed type assertion; falling back to database")
		f.keyCache.Delete(hash)
	}
	a, err := f.repo.FindByAPIKeyHash(ctx, hash)
	if err != nil {
		return nil, err
	}
	f.keyCache.Set(hash, a)
	return a, nil
}
