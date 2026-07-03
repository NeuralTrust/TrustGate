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
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type DeleteAuthHandler struct {
	deleter appauth.Deleter
}

func NewDeleteAuthHandler(deleter appauth.Deleter) *DeleteAuthHandler {
	return &DeleteAuthHandler{deleter: deleter}
}

// Handle godoc
// @Summary      Delete an auth
// @Description  Deletes an auth from a gateway.
// @Tags         auths
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path  string  true  "Gateway id"  format(uuid)
// @Param        id          path  string  true  "Auth id"     format(uuid)
// @Success      204         "No Content"
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/auths/{id} [delete]
func (h *DeleteAuthHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.AuthKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if err := h.deleter.Delete(c.UserContext(), gatewayID, id); err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteNoContent(c)
}
