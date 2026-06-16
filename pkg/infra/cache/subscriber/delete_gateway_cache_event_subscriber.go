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

package subscriber

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/event"
)

var _ cache.EventSubscriber[event.DeleteGatewayCacheEvent] = (*DeleteGatewayCacheEventSubscriber)(nil)

type DeleteGatewayCacheEventSubscriber struct {
	logger      *slog.Logger
	cache       cache.Client
	memoryCache *cache.TTLMap
}

func NewDeleteGatewayCacheEventSubscriber(
	logger *slog.Logger,
	c cache.Client,
) cache.EventSubscriber[event.DeleteGatewayCacheEvent] {
	return &DeleteGatewayCacheEventSubscriber{
		logger:      logger,
		cache:       c,
		memoryCache: c.GetTTLMap(cache.GatewayTTLName),
	}
}

func (s *DeleteGatewayCacheEventSubscriber) OnEvent(ctx context.Context, evt event.DeleteGatewayCacheEvent) error {
	s.logger.Info("invalidating gateway cache", slog.String("gateway_id", evt.GatewayID))

	if s.memoryCache != nil {
		deleteGatewayAliases(s.memoryCache, evt.GatewayID)
	}

	if err := s.cache.DeleteAllByGatewayID(ctx, evt.GatewayID); err != nil {
		s.logger.Warn("failed to delete gateway from redis cache",
			slog.String("gateway_id", evt.GatewayID),
			slog.String("error", err.Error()),
		)
	}

	return nil
}
