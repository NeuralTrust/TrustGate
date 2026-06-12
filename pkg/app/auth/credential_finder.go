package auth

import (
	"context"
	"log/slog"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
)

//go:generate mockery --name=CredentialFinder --dir=. --output=./mocks --filename=auth_credential_finder_mock.go --case=underscore --with-expecter
type CredentialFinder interface {
	OAuth2Auths(ctx context.Context) ([]*domain.Auth, error)
	MTLSAuths(ctx context.Context) ([]*domain.Auth, error)
}

var _ CredentialFinder = (*credentialFinder)(nil)

const (
	oauth2CacheKey = "enabled:oauth2"
	mtlsCacheKey   = "enabled:mtls"
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
