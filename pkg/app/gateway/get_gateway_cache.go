package gateway

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/google/uuid"
)

type GetGatewayCache interface {
	Retrieve(c context.Context, id string) (*types.GatewayDTO, error)
}

type getGatewayCache struct {
	cache cache.Client
}

func NewGetGatewayCache(cache cache.Client) GetGatewayCache {
	return &getGatewayCache{
		cache: cache,
	}
}

func (s *getGatewayCache) Retrieve(c context.Context, id string) (*types.GatewayDTO, error) {
	if err := s.validateGatewayID(id); err != nil {
		return nil, err
	}
	key := fmt.Sprintf("gateway:%s", id)
	gatewayJSON, err := s.cache.Get(c, key)
	if err != nil {
		return nil, err
	}

	var gateway types.GatewayDTO
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
