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

// Package invalidation publishes the cache-invalidation events that keep the
// in-memory read models of every admin replica coherent after a write.
package invalidation

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
)

// GatewayData asks every replica to drop the data it caches for gatewayID.
func GatewayData(
	ctx context.Context,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	gatewayID ids.GatewayID,
) {
	publish(ctx, publisher, logger,
		event.InvalidateGatewayDataEvent{GatewayID: gatewayID.String()},
		"failed to publish gateway data invalidation",
		slog.String("gateway_id", gatewayID.String()),
	)
}

// Registry asks every replica to drop the data it caches for one registry entry.
func Registry(
	ctx context.Context,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
) {
	publish(ctx, publisher, logger,
		event.InvalidateRegistryCacheEvent{
			GatewayID:  gatewayID.String(),
			RegistryID: registryID.String(),
		},
		"failed to publish backend cache invalidation",
		slog.String("gateway_id", gatewayID.String()),
		slog.String("registry_id", registryID.String()),
	)
}

// Publishing is best-effort: the write it announces already committed and cannot
// be rolled back, so a broker failure is logged instead of failing the caller.
// Deployments without an event bus wire a nil publisher.
func publish(
	ctx context.Context,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	evt event.Event,
	message string,
	attrs ...any,
) {
	if publisher == nil {
		return
	}
	err := publisher.Publish(ctx, evt)
	if err == nil || logger == nil {
		return
	}
	logger.Warn(message, append(attrs, slog.String("error", err.Error()))...)
}
