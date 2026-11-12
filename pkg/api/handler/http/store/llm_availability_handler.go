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

package store

import (
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	storeresponse "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store/response"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	"github.com/gofiber/fiber/v2"
)

type LLMAvailabilityHandler struct {
	service appstore.LLMAvailabilityService
}

func NewLLMAvailabilityHandler(service appstore.LLMAvailabilityService) *LLMAvailabilityHandler {
	return &LLMAvailabilityHandler{service: service}
}

// Get godoc
// @Summary      Get whether the gateway serves the LLM Store
// @Description  Says whether the gateway's data planes serve the LLM Store (/store/v1 with personal keys). Hosted and dedicated gateways always do. A hybrid gateway does when every data-plane instance seen in the last five minutes reports min_version or later; otherwise reason is no_data_plane, version_unknown (no heartbeat, or a version that is not semver) or data_plane_outdated with the lowest version seen. Personal consumers and keys can be written either way; they take effect once the data plane is recent enough.
// @Tags         store
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"  format(uuid)
// @Success      200         {object}  storeresponse.LLMAvailability
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      500         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/store/llm-availability [get]
func (h *LLMAvailabilityHandler) Get(c *fiber.Ctx) error {
	gatewayID, err := httpio.ParseGatewayID(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	got, err := h.service.LLMAvailability(c.UserContext(), gatewayID)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, storeresponse.LLMAvailability{
		Available:     got.Available,
		Reason:        string(got.Reason),
		MinVersion:    got.MinVersion,
		LowestVersion: got.LowestVersion,
	})
}
