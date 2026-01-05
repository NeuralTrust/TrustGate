package apikey

import (
	"context"
	"errors"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/iam/apikey"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/sirupsen/logrus"
)

var ErrInvalidCacheType = errors.New("invalid type assertion for apikey model")

//go:generate mockery --name=Finder --dir=. --output=./mocks --filename=apikey_data_finder_mock.go --case=underscore --with-expecter
type Finder interface {
	Find(ctx context.Context, key string) (*domain.APIKey, error)
}

type finder struct {
	repo        domain.Repository
	cache       cache.Client
	memoryCache *cache.TTLMap
	logger      *logrus.Logger
}

func NewFinder(
	repository domain.Repository,
	c cache.Client,
	logger *logrus.Logger,
) Finder {
	return &finder{
		repo:        repository,
		cache:       c,
		logger:      logger,
		memoryCache: c.GetTTLMap(cache.ApiKeyTTLName),
	}
}

func (f *finder) Find(ctx context.Context, key string) (*domain.APIKey, error) {
	if entity, err := f.getFromMemoryCache(key); err == nil {
		return entity, nil
	} else if !errors.Is(err, ErrInvalidCacheType) {
		f.logger.WithError(err).Debug("memory cache read apikey failure")
	}

	if cachedService, err := f.cache.GetApiKey(ctx, key); err == nil && cachedService != nil {
		f.saveToMemoryCache(ctx, cachedService)
		return cachedService, nil
	} else if err != nil {
		f.logger.WithError(err).Warn("distributed cache read apikey failure")
	}

	entity, err := f.repo.GetByKey(ctx, key)
	if err != nil {
		f.logger.WithError(err).Error("failed to fetch apikey from repository")
		return nil, err
	}

	f.saveToMemoryCache(ctx, entity)
	return entity, nil
}

func (f *finder) getFromMemoryCache(key string) (*domain.APIKey, error) {
	cachedValue, found := f.memoryCache.Get(key)
	if !found {
		return nil, errors.New("apiKey not found in memory cache")
	}

	entity, ok := cachedValue.(*domain.APIKey)
	if !ok {
		return nil, ErrInvalidCacheType
	}

	return entity, nil
}

func (f *finder) saveToMemoryCache(ctx context.Context, entity *domain.APIKey) {
	f.memoryCache.Set(entity.Key, entity)
	err := f.cache.SaveAPIKey(ctx, entity)
	if err != nil {
		f.logger.WithError(err).Error("failed to save apikey to distributed cache")
	}
}
