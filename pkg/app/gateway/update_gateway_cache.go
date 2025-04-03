package gateway

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/google/uuid"
)

type UpdateGatewayCache interface {
	Update(ctx context.Context, gateway *gateway.Gateway) error
}

type updateGatewayCache struct {
	transformer *OutputTransformer
	cache       *cache.Cache
}

func NewUpdateGatewayCache(cache *cache.Cache) UpdateGatewayCache {
	return &updateGatewayCache{
		transformer: NewOutputTransformer(),
		cache:       cache,
	}
}

func (h *updateGatewayCache) Update(ctx context.Context, gateway *gateway.Gateway) error {
	if err := h.validateGatewayID(gateway.ID.String()); err != nil {
		return fmt.Errorf("invalid gateway ID: %w", err)
	}

	apiGateway, err := h.transformer.Transform(gateway)
	if err != nil {
		return fmt.Errorf("failed to convert gateway: %w", err)
	}

	// Cache the gateway
	gatewayJSON, err := json.Marshal(apiGateway)
	if err != nil {
		return fmt.Errorf("failed to marshal gateway: %w", err)
	}

	key := fmt.Sprintf("gateway:%s", gateway.ID)
	if err := h.cache.Set(ctx, key, string(gatewayJSON), 0); err != nil {
		return fmt.Errorf("failed to cache gateway: %w", err)
	}

	return nil
}

func (h *updateGatewayCache) validateGatewayID(id string) error {
	if id == "" {
		return fmt.Errorf("gateway ID cannot be empty")
	}
	if _, err := uuid.Parse(id); err != nil {
		return fmt.Errorf("gateway ID must be a valid UUID: %v", err)
	}
	return nil
}
