package apikey

import (
	"context"
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	domainService "github.com/NeuralTrust/TrustGate/pkg/domain/apikey"
	"github.com/NeuralTrust/TrustGate/pkg/models"
	"github.com/sirupsen/logrus"
)

var ErrInvalidCacheType = errors.New("invalid type assertion for apikey model")

type Finder interface {
	Find(ctx context.Context, gatewayID string, key string) (*models.APIKey, error)
}

type finder struct {
	repo        domainService.Repository
	cache       *cache.Cache
	memoryCache *common.TTLMap
	logger      *logrus.Logger
}

func NewFinder(
	repository domainService.Repository,
	cache *cache.Cache,
	logger *logrus.Logger,
) Finder {
	return &finder{
		repo:        repository,
		cache:       cache,
		logger:      logger,
		memoryCache: cache.CreateTTLMap("apikey", common.ApiKeyCacheTTL),
	}
}

func (f *finder) Find(ctx context.Context, gatewayID string, key string) (*models.APIKey, error) {
	if entity, err := f.getFromMemoryCache(key); err == nil {
		return entity, nil
	} else if !errors.Is(err, ErrInvalidCacheType) {
		f.logger.WithError(err).Warn("memory cache read apikey failure")
	}

	if cachedService, err := f.cache.GetApiKey(ctx, gatewayID, key); err == nil && cachedService != nil {
		f.saveToMemoryCache(cachedService)
		return cachedService, nil
	} else if err != nil {
		f.logger.WithError(err).Warn("distributed cache read apikey failure")
	}

	entity, err := f.repo.GetByKey(ctx, gatewayID, key)
	if err != nil {
		f.logger.WithError(err).Error("failed to fetch apikey from repository")
		return nil, err
	}

	f.saveToMemoryCache(entity)
	return entity, nil
}

func (f *finder) getFromMemoryCache(key string) (*models.APIKey, error) {
	cachedValue, found := f.memoryCache.Get(key)
	if !found {
		return nil, errors.New("apiKey not found in memory cache")
	}

	entity, ok := cachedValue.(*models.APIKey)
	if !ok {
		return nil, ErrInvalidCacheType
	}

	return entity, nil
}

func (f *finder) saveToMemoryCache(entity *models.APIKey) {
	f.memoryCache.Set(entity.Key, entity)
}
