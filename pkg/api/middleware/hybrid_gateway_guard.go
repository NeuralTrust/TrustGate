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
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
	"github.com/gofiber/fiber/v2"
)

// ErrCodeHybridGateway is returned when a hosted proxy refuses a gateway whose
// entitlements bind it to a customer-run (hybrid) data plane.
const ErrCodeHybridGateway = "gateway_served_by_external_data_plane"

// HybridGatewayGuardMiddleware refuses to serve gateways stamped
// data_plane=hybrid on deployments that are not that data plane. It must run
// after the auth middleware resolved the gateway and before anything can act on
// the request body (plugins, forwarding, metrics), so no payload of a hybrid
// gateway is ever processed, exported, or stored by a hosted proxy.
type HybridGatewayGuardMiddleware struct {
	serveHybrid bool
}

func NewHybridGatewayGuardMiddleware(cfg *config.Config) *HybridGatewayGuardMiddleware {
	return &HybridGatewayGuardMiddleware{serveHybrid: cfg.Server.ServeHybridGateways}
}

func (m *HybridGatewayGuardMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		if m.serveHybrid {
			return c.Next()
		}
		gw, ok := appgateway.FromContext(c.UserContext())
		if !ok || !gw.ServedByHybridDataPlane() {
			return c.Next()
		}
		SetOpsOutcome(c, o11y.OutcomeDeniedForbidden)
		return c.Status(fiber.StatusMisdirectedRequest).JSON(httpio.ErrorBody{
			Error:   ErrCodeHybridGateway,
			Message: "this gateway is served by its own data plane; send requests to that data plane's proxy endpoint",
		})
	}
}
