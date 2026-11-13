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

package registry

import (
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/registry/response"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

// UserHeadersHandler serves the per-user header values of an MCP instance as
// an admin sees them: who holds one, resetting them, loading them in bulk and
// handing one person their link. Values are written, never read back.
type UserHeadersHandler struct {
	admin appregistry.UserHeaderAdmin
}

func NewUserHeadersHandler(admin appregistry.UserHeaderAdmin) *UserHeadersHandler {
	return &UserHeadersHandler{admin: admin}
}

// List godoc
// @Summary      List who holds per-user header values
// @Description  Lists every person holding a value for this MCP instance's per-user headers, when each was written and whether the upstream refused it. Values are never returned.
// @Tags         registries
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string  true  "Gateway id"   format(uuid)
// @Param        id          path      string  true  "Registry id"  format(uuid)
// @Success      200         {object}  response.UserHeaderHoldersResponse
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/{id}/user-headers [get]
func (h *UserHeadersHandler) List(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.RegistryKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	holders, err := h.admin.Holders(c.UserContext(), gatewayID, id)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromUserHeaderHolders(holders))
}

// Reset godoc
// @Summary      Reset per-user header values
// @Description  Removes the values one person holds for this instance (principal_sub), or every person's when principal_sub is omitted. The next call of each affected person answers with a connect link.
// @Tags         registries
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id     path      string  true   "Gateway id"   format(uuid)
// @Param        id             path      string  true   "Registry id"  format(uuid)
// @Param        principal_sub  query     string  false  "One person; omitted resets everyone"
// @Success      200            {object}  response.UserHeaderCountResponse
// @Failure      404            {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/{id}/user-headers/values [delete]
func (h *UserHeadersHandler) Reset(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.RegistryKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	n, err := h.admin.Reset(c.UserContext(), gatewayID, id, strings.TrimSpace(c.Query("principal_sub")))
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.UserHeaderCountResponse{Count: n})
}

// Import godoc
// @Summary      Load per-user header values in bulk
// @Description  Stores values for many people at once (up to 1000 rows). Every row is validated before any is written; values are encrypted and never returned.
// @Tags         registries
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                           true  "Gateway id"   format(uuid)
// @Param        id          path      string                           true  "Registry id"  format(uuid)
// @Param        body        body      request.UserHeaderImportRequest  true  "Values to load"
// @Success      200         {object}  response.UserHeaderCountResponse
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/{id}/user-headers/values [put]
func (h *UserHeadersHandler) Import(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.RegistryKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req request.UserHeaderImportRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	rows := make([]appregistry.UserHeaderImportRow, 0, len(req.Values))
	for _, v := range req.Values {
		rows = append(rows, appregistry.UserHeaderImportRow{PrincipalSub: v.PrincipalSub, Header: v.Header, Value: v.Value})
	}
	n, err := h.admin.Import(c.UserContext(), gatewayID, id, rows)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.UserHeaderCountResponse{Count: n})
}

// Link godoc
// @Summary      Issue one person's link to enter their header values
// @Description  Mints the connect page one person walks to enter their own values for this instance. Hand it to that person: it acts as them.
// @Tags         registries
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                         true  "Gateway id"   format(uuid)
// @Param        id          path      string                         true  "Registry id"  format(uuid)
// @Param        body        body      request.UserHeaderLinkRequest  true  "Whose link"
// @Success      200         {object}  response.UserHeaderLinkResponse
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody
// @Failure      422         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/registries/{id}/user-headers/links [post]
func (h *UserHeadersHandler) Link(c *fiber.Ctx) error {
	gatewayID, id, err := httpio.ParseGatewayScopedID[ids.RegistryKind](c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	var req request.UserHeaderLinkRequest
	if err := c.BodyParser(&req); err != nil {
		return httpio.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	link, err := h.admin.Link(c.UserContext(), gatewayID, id, req.PrincipalSub, req.ConsumerPath, req.ResumeURL)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteOK(c, response.FromUserHeaderLink(link))
}
