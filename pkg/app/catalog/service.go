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

package catalog

import (
	"context"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
)

//go:generate mockery --name=Service --dir=. --output=./mocks --filename=catalog_service_mock.go --case=underscore --with-expecter
type Service interface {
	ListProviders(ctx context.Context) ([]domain.Provider, error)
	ListModels(ctx context.Context, providerCode string) ([]domain.Model, error)
}

var _ Service = (*service)(nil)

type service struct {
	repo domain.Repository
}

func NewService(repo domain.Repository) Service {
	return &service{repo: repo}
}

func (s *service) ListProviders(ctx context.Context) ([]domain.Provider, error) {
	return s.repo.ListProviders(ctx)
}

func (s *service) ListModels(ctx context.Context, providerCode string) ([]domain.Model, error) {
	return s.repo.ListModelsByProviderCode(ctx, providerCode)
}
