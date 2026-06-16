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

package auth

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/event"
)

// publishGatewayDataInvalidation is best-effort: a publish error is logged, never
// returned, because the database write already succeeded.
func publishGatewayDataInvalidation(
	ctx context.Context,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	gatewayID ids.GatewayID,
) {
	evt := event.InvalidateGatewayDataEvent{GatewayID: gatewayID.String()}
	if err := publisher.Publish(ctx, evt); err != nil {
		logger.Warn("failed to publish gateway data invalidation",
			slog.String("gateway_id", gatewayID.String()),
			slog.String("error", err.Error()),
		)
	}
}
