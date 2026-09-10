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
	"errors"
	"fmt"

	catalogresponse "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/catalog/response"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/jwt"
	"github.com/gofiber/fiber/v2"
)

type ListRegistryModelsHandler struct {
	verifier     jwt.ProxyTokenVerifier
	finder       appregistry.Finder
	service      appcatalog.Service
	availability appcatalog.RegistryAvailability
}

func NewListRegistryModelsHandler(
	verifier jwt.ProxyTokenVerifier,
	finder appregistry.Finder,
	service appcatalog.Service,
	availability appcatalog.RegistryAvailability,
) *ListRegistryModelsHandler {
	return &ListRegistryModelsHandler{
		verifier:     verifier,
		finder:       finder,
		service:      service,
		availability: availability,
	}
}

// Handle godoc
// @Summary      List a registry's available models from the data plane
// @Description  Returns the model catalog narrowed to what this registry's credentials can actually invoke, resolved from this data plane's own network: AWS Bedrock registries are checked against the AWS control plane, every other provider against its authenticated models listing. It answers the same shape as the admin catalog endpoint, and exists because on a hybrid deployment only this plane can reach a provider endpoint that lives inside the customer's network. Authorized by a control-plane-minted diagnostics token bound to the gateway. A registry that has not reached this plane's config snapshot yet answers 404, so the caller can fall back to the unnarrowed catalog.
// @Tags         diagnostics
// @Produce      json
// @Param        X-AG-Diagnostics-Token  header    string  true  "Control-plane-minted diagnostics JWT"
// @Param        gateway_id              path      string  true  "Gateway id"   format(uuid)
// @Param        registry_id             path      string  true  "Registry id"  format(uuid)
// @Success      200                     {object}  map[string][]catalogresponse.ModelResponse
// @Failure      401                     {object}  httpio.ErrorBody
// @Failure      404                     {object}  httpio.ErrorBody
// @Router       /__diagnostics/gateways/{gateway_id}/registries/{registry_id}/models [get]
func (h *ListRegistryModelsHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	registryID, err := httpio.ParseUUIDParam[ids.RegistryKind](c, "registry_id")
	if err != nil {
		return httpio.WriteError(c, err)
	}

	if !authorizeGateway(c, h.verifier, gatewayID) {
		return unauthorized(c)
	}

	// The registry is the authority on its own provider, so it is read rather
	// than taken from the caller: a mismatch would silently skip the narrowing.
	reg, err := h.finder.FindByID(c.UserContext(), gatewayID, registryID)
	if err != nil {
		if errors.Is(err, commonerrors.ErrNotFound) {
			// A registry this plane's snapshot does not carry yet is a
			// propagation race, not a missing registry. Callers treat the 404
			// as "narrowing unavailable" and fall back to the unnarrowed
			// catalog, so the distinction only needs to reach our own logs.
			return httpio.WriteError(c, fmt.Errorf(
				"registry has not reached this data plane's config snapshot yet: %w", commonerrors.ErrNotFound))
		}
		return httpio.WriteError(c, err)
	}

	models, err := h.service.ListModels(c.UserContext(), reg.Provider())
	if err != nil {
		return httpio.WriteError(c, err)
	}
	models = h.availability.Narrow(c.UserContext(), appcatalog.ServerlessFilterInput{
		ProviderCode: reg.Provider(),
		GatewayID:    gatewayID,
		RegistryID:   registryID,
		Models:       models,
	})

	out := make([]catalogresponse.ModelResponse, 0, len(models))
	for _, m := range models {
		out = append(out, catalogresponse.FromModel(m))
	}
	return httpio.WriteOK(c, fiber.Map{"items": out})
}
