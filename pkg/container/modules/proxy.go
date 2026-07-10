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

	proxyhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/proxy"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
)

func Proxy(c *container.Container) error {
	if err := c.Provide(approuting.NewResolver); err != nil {
		return err
	}
	// NewProviderInvoker depends on a segregated codec view; the concrete adapter
	// registry satisfies it, but dig resolves by exact type so we bind it here.
	if err := c.Provide(func(locator factory.ProviderLocator, registry *adapter.Registry, logger *slog.Logger) appproxy.ProviderInvoker {
		return appproxy.NewProviderInvoker(locator, registry, logger)
	}); err != nil {
		return err
	}
	// The forwarder's load balancer only needs the Redis accessor; expose the
	// cache client under that narrow view (dig resolves by exact type).
	if err := c.Provide(func(client cache.Client) loadbalancer.RedisProvider { return client }); err != nil {
		return err
	}
	if err := c.Provide(appproxy.NewForwarder); err != nil {
		return err
	}
	return c.Provide(proxyhttp.NewForwardedHandler)
}
