package gateway

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/google/uuid"
)

type GetGatewayCache interface {
	Retrieve(c context.Context, id string) (*types.Gateway, error)
}

type getGatewayCache struct {
	cache *cache.Cache
}

func NewGetGatewayCache(cache *cache.Cache) GetGatewayCache {
	return &getGatewayCache{
		cache: cache,
	}
}

func (s *getGatewayCache) Retrieve(c context.Context, id string) (*types.Gateway, error) {
	if err := s.validateGatewayID(id); err != nil {
		return nil, err
	}
	key := fmt.Sprintf("gateway:%s", id)
	gatewayJSON, err := s.cache.Get(c, key)
	if err != nil {
		return nil, err
	}

	var gateway types.Gateway
	if err := json.Unmarshal([]byte(gatewayJSON), &gateway); err != nil {
		return nil, err
	}

	return &gateway, nil
}

func (s *getGatewayCache) validateGatewayID(id string) error {
	if id == "" {
		return fmt.Errorf("gateway ID cannot be empty")
	}
	if _, err := uuid.Parse(id); err != nil {
		return fmt.Errorf("gateway ID must be a valid UUID: %v", err)
	}
	return nil
}
