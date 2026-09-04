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

// Package diagnostics exposes control-plane-driven probes on the proxy plane,
// so connectivity checks run from the network that actually serves the
// gateway's traffic. On a hybrid deployment that is the customer's network —
// the only vantage point where a registry test-connection result means
// anything.
package diagnostics

import (
	"errors"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	registryrequest "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/request"
	registryresponse "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/response"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	"github.com/gofiber/fiber/v2"
)

// HeaderDiagnosticsToken carries the short-lived, control-plane-minted JWT that
// authorizes a diagnostics probe. RS256 tokens are verified against the issuer
// keys distributed via config-sync; HS256 against the local SERVER_SECRET_KEY.
const HeaderDiagnosticsToken = "X-AG-Diagnostics-Token" // #nosec G101 -- HTTP header name, not a credential

// StageNotSynced reports a by-id probe whose registry has not reached this
// data plane's config snapshot yet — a freshly created registry races the
// config-sync push, so the caller should retry rather than treat it as broken.
const StageNotSynced = "not_synced"

type TestConnectionHandler struct {
	verifier jwt.ProxyTokenVerifier
	tester   appregistry.ConnectionTester
}

func NewTestConnectionHandler(verifier jwt.ProxyTokenVerifier, tester appregistry.ConnectionTester) *TestConnectionHandler {
	return &TestConnectionHandler{verifier: verifier, tester: tester}
}

// Handle godoc
// @Summary      Test a backend connection from the data plane
// @Description  Runs the registry connection probe from this data plane's own network, so the result reflects what serving traffic will actually reach. Authorized by a control-plane-minted diagnostics token bound to the gateway. Accepts the same body as the admin test-connection endpoint: a stored registry (registry_id, which must have synced to this plane — stage "not_synced" means retry) or an inline candidate (provider + auth).
// @Tags         diagnostics
// @Accept       json
// @Produce      json
// @Param        X-AG-Diagnostics-Token  header    string                                 true  "Control-plane-minted diagnostics JWT"
// @Param        gateway_id              path      string                                 true  "Gateway id"  format(uuid)
// @Param        body                    body      registryrequest.TestConnectionRequest  true  "Connection to test"
// @Success      200                     {object}  registryresponse.TestConnectionResponse
// @Failure      400                     {object}  httpio.ErrorBody
// @Failure      401                     {object}  httpio.ErrorBody
// @Router       /__diagnostics/gateways/{gateway_id}/registries/test-connection [post]
func (h *TestConnectionHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}

	token := c.Get(HeaderDiagnosticsToken)
	if token == "" {
		return unauthorized(c)
	}
	claims, err := h.verifier.Verify(token)
	if err != nil {
		return unauthorized(c)
	}
	if claims.Purpose != jwt.PurposeDiagnostics {
		return unauthorized(c)
	}
	// The token is bound to one gateway; a leaked one cannot probe another.
	if claims.GatewayID == "" || claims.GatewayID != gatewayID.String() {
		return unauthorized(c)
	}

	var req registryrequest.TestConnectionRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	req.Normalize()
	if err := req.Validate(); err != nil {
		return httpio.WriteError(c, err)
	}

	in := appregistry.TestConnectionInput{GatewayID: gatewayID}
	if req.IsByID() {
		registryID, err := ids.Parse[ids.RegistryKind](req.RegistryID)
		if err != nil {
			return httpio.WriteError(c, fmt.Errorf("invalid registry_id: %w", commonerrors.ErrValidation))
		}
		in.RegistryID = &registryID
	} else {
		in.Provider = req.Provider
		in.ProviderOptions = req.ProviderOptions
		in.Auth = req.ToAuth()
	}

	result, err := h.tester.Test(c.UserContext(), in)
	if err != nil {
		// A by-id probe for a registry this plane's snapshot does not carry yet
		// is a propagation race, not a broken connection: report it as its own
		// stage so the caller can retry once config-sync catches up.
		if in.RegistryID != nil && errors.Is(err, commonerrors.ErrNotFound) {
			return httpio.WriteOK(c, registryresponse.FromTestConnectionResult(appregistry.TestConnectionResult{
				OK:      false,
				Stage:   StageNotSynced,
				Message: "registry has not reached this data plane's config snapshot yet; retry shortly",
			}))
		}
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, registryresponse.FromTestConnectionResult(result))
}

func unauthorized(c *fiber.Ctx) error {
	return c.Status(fiber.StatusUnauthorized).JSON(httpio.ErrorBody{Error: "unauthenticated"})
}
