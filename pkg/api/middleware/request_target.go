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

package middleware

import (
	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
)

func stampRequestTarget(c *fiber.Ctx, req *infracontext.RequestContext) {
	if req == nil {
		return
	}
	if route, ok := proxyRouteFor(c); ok {
		req.SourceFormat = string(route.SourceFormat)
		req.ProxyCapability = string(route.Capability)
	}
	req.RequestedModel = appproxy.RequestedModelRef(req)
}

func proxyRouteFor(c *fiber.Ctx) (resolver.ProxyRoute, bool) {
	if route, ok := c.Locals(resolver.ProxyRouteLocalsKey).(resolver.ProxyRoute); ok {
		return route, true
	}
	route, err := resolver.ResolveProxyPath(c.Path())
	if err != nil {
		return resolver.ProxyRoute{}, false
	}
	return route, true
}
