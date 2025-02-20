package service

import (
	"context"
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/common"
	domainService "github.com/NeuralTrust/TrustGate/pkg/domain/service"
	"github.com/NeuralTrust/TrustGate/pkg/models"
	"github.com/sirupsen/logrus"
)

var ErrInvalidCacheType = errors.New("invalid type assertion for service model")

type Finder interface {
	Find(ctx context.Context, gatewayID string, serviceID string) (*models.Service, error)
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
		memoryCache: cache.CreateTTLMap("service", common.ServiceCacheTTL),
	}
}

func (f *finder) Find(ctx context.Context, gatewayID, serviceID string) (*models.Service, error) {

	if service, err := f.getServiceFromMemoryCache(serviceID); err == nil {
		return service, nil
	} else if !errors.Is(err, ErrInvalidCacheType) {
		f.logger.WithError(err).Warn("memory cache read service failure")
	}

	if cachedService, err := f.cache.GetService(ctx, gatewayID, serviceID); err == nil && cachedService != nil {
		f.saveServiceToMemoryCache(cachedService)
		return cachedService, nil
	} else if err != nil {
		f.logger.WithError(err).Warn("distributed cache read service failure")
	}

	service, err := f.repo.GetService(ctx, serviceID)
	if err != nil {
		f.logger.WithError(err).Error("failed to fetch service from repository")
		return nil, err
	}

	f.saveServiceToMemoryCache(service)
	return service, nil
}

func (f *finder) getServiceFromMemoryCache(serviceID string) (*models.Service, error) {
	cachedValue, found := f.memoryCache.Get(serviceID)
	if !found {
		return nil, errors.New("service not found in memory cache")
	}

	service, ok := cachedValue.(*models.Service)
	if !ok {
		return nil, ErrInvalidCacheType
	}

	return service, nil
}

func (f *finder) saveServiceToMemoryCache(service *models.Service) {
	f.memoryCache.Set(service.ID, service)
}
