package service

import (
	"context"
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	domainService "github.com/NeuralTrust/TrustGate/pkg/domain/service"
	"github.com/sirupsen/logrus"
)

var ErrInvalidCacheType = errors.New("invalid type assertion for service model")

type Finder interface {
	Find(ctx context.Context, gatewayID string, serviceID string) (*domainService.Service, error)
}

type finder struct {
	repo        domainService.Repository
	cache       cache.Cache
	memoryCache *cache.TTLMap
	logger      *logrus.Logger
}

func NewFinder(
	repository domainService.Repository,
	c cache.Cache,
	logger *logrus.Logger,
) Finder {
	return &finder{
		repo:        repository,
		cache:       c,
		logger:      logger,
		memoryCache: c.GetTTLMap(cache.ServiceTTLName),
	}
}

func (f *finder) Find(ctx context.Context, gatewayID, serviceID string) (*domainService.Service, error) {

	if service, err := f.getServiceFromMemoryCache(serviceID); err == nil {
		return service, nil
	} else if !errors.Is(err, ErrInvalidCacheType) {
		f.logger.WithError(err).Debug("memory cache read service failure")
	}

	if cachedService, err := f.cache.GetService(ctx, gatewayID, serviceID); err == nil && cachedService != nil {
		f.saveServiceToMemoryCache(ctx, cachedService)
		return cachedService, nil
	} else if err != nil {
		f.logger.WithError(err).Debug("distributed cache read service failure")
	}

	service, err := f.repo.Get(ctx, serviceID)
	if err != nil {
		f.logger.WithError(err).Error("failed to fetch service from repository")
		return nil, err
	}

	f.saveServiceToMemoryCache(ctx, service)
	return service, nil
}

func (f *finder) getServiceFromMemoryCache(serviceID string) (*domainService.Service, error) {
	cachedValue, found := f.memoryCache.Get(serviceID)
	if !found {
		return nil, errors.New("service not found in memory cache")
	}

	service, ok := cachedValue.(*domainService.Service)
	if !ok {
		return nil, ErrInvalidCacheType
	}

	return service, nil
}

func (f *finder) saveServiceToMemoryCache(ctx context.Context, service *domainService.Service) {
	f.memoryCache.Set(service.ID.String(), service)
	err := f.cache.SaveService(ctx, service.GatewayID.String(), service)
	if err != nil {
		f.logger.WithError(err).Error("failed to save service to distributed cache")
	}
}
