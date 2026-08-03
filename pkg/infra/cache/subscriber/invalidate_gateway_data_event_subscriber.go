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

	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
)

var _ cache.EventSubscriber[event.InvalidateGatewayDataEvent] = (*InvalidateGatewayDataEventSubscriber)(nil)

// InvalidateGatewayDataEventSubscriber drops the in-process caches that hold
// gateway-scoped configuration. It must never delete from Redis: that keyspace
// holds durable OAuth state (user credentials, client registrations, sessions)
// rather than cached config, which now reaches data planes over config-sync.
type InvalidateGatewayDataEventSubscriber struct {
	logger            *slog.Logger
	gatewayCache      *cache.TTLMap
	consumerCache     *cache.TTLMap
	consumerDataCache *cache.TTLMap
	loadBalancerCache *cache.TTLMap
	authCache         *cache.TTLMap
	consumerPathCache *cache.TTLMap
	roleCache         *cache.TTLMap
	registryCache     *cache.TTLMap
	policyCache       *cache.TTLMap
}

func NewInvalidateGatewayDataEventSubscriber(
	logger *slog.Logger,
	c cache.Client,
) cache.EventSubscriber[event.InvalidateGatewayDataEvent] {
	return &InvalidateGatewayDataEventSubscriber{
		logger:            logger,
		gatewayCache:      c.GetTTLMap(cache.GatewayTTLName),
		consumerCache:     c.GetTTLMap(cache.ConsumerTTLName),
		consumerDataCache: c.GetTTLMap(cache.ConsumerDataTTLName),
		loadBalancerCache: c.GetTTLMap(cache.LoadBalancerTTLName),
		authCache:         c.GetTTLMap(cache.AuthTTLName),
		consumerPathCache: c.GetTTLMap(cache.ConsumerPathTTLName),
		roleCache:         c.GetTTLMap(cache.RoleTTLName),
		registryCache:     c.GetTTLMap(cache.RegistryTTLName),
		policyCache:       c.GetTTLMap(cache.PolicyTTLName),
	}
}

func (s *InvalidateGatewayDataEventSubscriber) OnEvent(_ context.Context, evt event.InvalidateGatewayDataEvent) error {
	s.logger.Info("invalidating gateway data cache", slog.String("gateway_id", evt.GatewayID))

	if s.gatewayCache != nil {
		deleteGatewayAliases(s.gatewayCache, evt.GatewayID)
	}
	if s.consumerCache != nil {
		s.consumerCache.Clear()
	}
	if s.consumerDataCache != nil {
		s.consumerDataCache.Delete(evt.GatewayID)
	}
	if s.loadBalancerCache != nil {
		s.loadBalancerCache.DeleteByPrefix(evt.GatewayID + ":")
	}
	if s.authCache != nil {
		s.authCache.Clear()
	}
	if s.consumerPathCache != nil {
		s.consumerPathCache.Clear()
	}
	if s.roleCache != nil {
		s.roleCache.Clear()
	}
	if s.registryCache != nil {
		s.registryCache.Clear()
	}
	if s.policyCache != nil {
		s.policyCache.Clear()
	}

	return nil
}

func deleteGatewayAliases(gatewayCache *cache.TTLMap, gatewayID string) {
	slug := cachedGatewaySlug(gatewayCache, gatewayID)
	gatewayCache.Delete("id:" + gatewayID)
	if slug != "" {
		gatewayCache.Delete("slug:" + slug)
	}
}

func cachedGatewaySlug(gatewayCache *cache.TTLMap, gatewayID string) string {
	cached, ok := gatewayCache.Get("id:" + gatewayID)
	if !ok {
		return ""
	}
	gw, ok := cached.(*gatewaydomain.Gateway)
	if !ok || gw.Slug == "" {
		return ""
	}
	return gatewaydomain.NormalizeSlug(gw.Slug)
}
