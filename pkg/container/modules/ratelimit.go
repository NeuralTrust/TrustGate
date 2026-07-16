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

package modules

import (
	"log/slog"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	inforatelimit "github.com/NeuralTrust/TrustGate/pkg/infra/ratelimit"
)

// RateLimit wires the gateway plan rate limiter shared by the proxy Forwarder
// and the MCP RPCGateway. It reuses the process Redis client (already
// selecting DB 3) rather than opening a dedicated connection.
func RateLimit(c *container.Container) error {
	if err := c.Provide(func(finder appgateway.Finder) ratelimitapp.GatewayTierLoader {
		return ratelimitapp.NewGatewayTierLoader(finder)
	}); err != nil {
		return err
	}
	if err := c.Provide(func(client cache.Client, logger *slog.Logger) ratelimitapp.Counter {
		return inforatelimit.NewStore(client.RedisClient(), logger)
	}); err != nil {
		return err
	}
	return c.Provide(func(
		tiers ratelimitapp.GatewayTierLoader,
		counter ratelimitapp.Counter,
		cfg *config.Config,
		logger *slog.Logger,
	) ratelimitapp.Checker {
		if !cfg.RateLimit.Enabled {
			return ratelimitapp.NewNoopChecker()
		}
		return ratelimitapp.NewChecker(tiers, counter, logger)
	})
}
