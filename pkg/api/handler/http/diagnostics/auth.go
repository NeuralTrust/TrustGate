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

package diagnostics

import (
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	"github.com/gofiber/fiber/v2"
)

// HeaderDiagnosticsToken carries the short-lived, control-plane-minted JWT that
// authorizes a diagnostics probe. RS256 tokens are verified against the issuer
// keys distributed via config-sync; HS256 against the local SERVER_SECRET_KEY.
const HeaderDiagnosticsToken = "X-AG-Diagnostics-Token" // #nosec G101 -- HTTP header name, not a credential

// authorizeGateway accepts a request only when it carries a diagnostics token
// minted for this exact gateway. Every probe on this plane shares the check, so
// none can be reached with an admin, playground or service token, and a leaked
// diagnostics token cannot be pointed at another gateway.
func authorizeGateway(c *fiber.Ctx, verifier jwt.ProxyTokenVerifier, gatewayID ids.GatewayID) bool {
	token := c.Get(HeaderDiagnosticsToken)
	if token == "" {
		return false
	}
	claims, err := verifier.Verify(token)
	if err != nil {
		return false
	}
	if claims.Purpose != jwt.PurposeDiagnostics {
		return false
	}
	return claims.GatewayID != "" && claims.GatewayID == gatewayID.String()
}

func unauthorized(c *fiber.Ctx) error {
	return c.Status(fiber.StatusUnauthorized).JSON(httpio.ErrorBody{Error: "unauthenticated"})
}
