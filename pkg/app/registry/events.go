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

package registry

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
)

// publishBackendCacheInvalidation is best-effort: a publish error is logged, never
// returned, because the database write already succeeded.
func publishBackendCacheInvalidation(
	ctx context.Context,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	gatewayID ids.GatewayID, backendID ids.RegistryID,
) {
	evt := event.InvalidateRegistryCacheEvent{
		GatewayID:  gatewayID.String(),
		RegistryID: backendID.String(),
	}
	if err := publisher.Publish(ctx, evt); err != nil {
		logger.Warn("failed to publish backend cache invalidation",
			slog.String("gateway_id", gatewayID.String()),
			slog.String("registry_id", backendID.String()),
			slog.String("error", err.Error()),
		)
	}
}
