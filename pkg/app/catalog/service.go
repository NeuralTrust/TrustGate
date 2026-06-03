package catalog

import (
	"context"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/catalog"
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
