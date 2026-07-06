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

package consumer

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/consumer/request"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type AssociationHandler struct {
	associator appconsumer.Associator
}

func NewAssociationHandler(associator appconsumer.Associator) *AssociationHandler {
	return &AssociationHandler{associator: associator}
}

// AttachRegistry godoc
// @Summary      Attach a registry to a consumer
// @Description  Associates a registry with a consumer (idempotent). The optional body sets the registry weight for weighted load balancing.
// @Tags         consumers
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id   path  string                          true   "Gateway id"   format(uuid)
// @Param        id           path  string                          true   "Consumer id"  format(uuid)
// @Param        registry_id  path  string                          true   "Registry id"  format(uuid)
// @Param        body         body  request.AttachRegistryRequest   false  "Optional registry weight"
// @Success      204          "No Content"
// @Failure      400          {object}  httpio.ErrorBody
// @Failure      401          {object}  httpio.ErrorBody
// @Failure      404          {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/consumers/{id}/registries/{registry_id} [post]
func (h *AssociationHandler) AttachRegistry(c *fiber.Ctx) error {
	gatewayID, consumerID, registryID, err := httpio.ParseConsumerAssociationID[ids.RegistryKind](c, "registry_id")
	if err != nil {
		return httpio.WriteError(c, err)
	}
	weight, err := parseAttachRegistryWeight(c)
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if err := h.associator.AttachRegistry(c.UserContext(), gatewayID, consumerID, registryID, weight); err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteNoContent(c)
}

func parseAttachRegistryWeight(c *fiber.Ctx) (*int, error) {
	if len(c.Body()) == 0 {
		return nil, nil
	}
	var req request.AttachRegistryRequest
	if err := c.BodyParser(&req); err != nil {
		return nil, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation)
	}
	if req.Weight == nil {
		return nil, nil
	}
	if *req.Weight < consumerdomain.DefaultRegistryWeight || *req.Weight > consumerdomain.MaxRegistryWeight {
		return nil, fmt.Errorf(
			"weight must be between %d and %d: %w",
			consumerdomain.DefaultRegistryWeight, consumerdomain.MaxRegistryWeight, commonerrors.ErrValidation,
		)
	}
	return req.Weight, nil
}

// DetachRegistry godoc
// @Summary      Detach a registry from a consumer
// @Description  Removes the association between a registry and a consumer (idempotent).
// @Tags         consumers
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id   path  string  true  "Gateway id"   format(uuid)
// @Param        id           path  string  true  "Consumer id"  format(uuid)
// @Param        registry_id  path  string  true  "Registry id"  format(uuid)
// @Success      204          "No Content"
// @Failure      400          {object}  httpio.ErrorBody
// @Failure      401          {object}  httpio.ErrorBody
// @Failure      404          {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/consumers/{id}/registries/{registry_id} [delete]
func (h *AssociationHandler) DetachRegistry(c *fiber.Ctx) error {
	gatewayID, consumerID, registryID, err := httpio.ParseConsumerAssociationID[ids.RegistryKind](c, "registry_id")
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if err := h.associator.DetachRegistry(c.UserContext(), gatewayID, consumerID, registryID); err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteNoContent(c)
}

// AttachRole godoc
// @Summary      Attach a role to a consumer
// @Description  Associates a role with a role_based consumer (idempotent). Returns 409 for inline consumers.
// @Tags         consumers
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path  string  true  "Gateway id"   format(uuid)
// @Param        id          path  string  true  "Consumer id"  format(uuid)
// @Param        role_id     path  string  true  "Role id"      format(uuid)
// @Success      204         "No Content"
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Failure      409         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/consumers/{id}/roles/{role_id} [post]
func (h *AssociationHandler) AttachRole(c *fiber.Ctx) error {
	gatewayID, consumerID, roleID, err := httpio.ParseConsumerAssociationID[ids.RoleKind](c, "role_id")
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if err := h.associator.AttachRole(c.UserContext(), gatewayID, consumerID, roleID); err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteNoContent(c)
}

// DetachRole godoc
// @Summary      Detach a role from a consumer
// @Description  Removes the association between a role and a consumer (idempotent).
// @Tags         consumers
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path  string  true  "Gateway id"   format(uuid)
// @Param        id          path  string  true  "Consumer id"  format(uuid)
// @Param        role_id     path  string  true  "Role id"      format(uuid)
// @Success      204         "No Content"
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/consumers/{id}/roles/{role_id} [delete]
func (h *AssociationHandler) DetachRole(c *fiber.Ctx) error {
	gatewayID, consumerID, roleID, err := httpio.ParseConsumerAssociationID[ids.RoleKind](c, "role_id")
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if err := h.associator.DetachRole(c.UserContext(), gatewayID, consumerID, roleID); err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteNoContent(c)
}

// AttachAuth godoc
// @Summary      Attach an auth to a consumer
// @Description  Associates an auth credential with a consumer (idempotent).
// @Tags         consumers
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path  string  true  "Gateway id"   format(uuid)
// @Param        id          path  string  true  "Consumer id"  format(uuid)
// @Param        auth_id     path  string  true  "Auth id"      format(uuid)
// @Success      204         "No Content"
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/consumers/{id}/auths/{auth_id} [post]
func (h *AssociationHandler) AttachAuth(c *fiber.Ctx) error {
	gatewayID, consumerID, authID, err := httpio.ParseConsumerAssociationID[ids.AuthKind](c, "auth_id")
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if err := h.associator.AttachAuth(c.UserContext(), gatewayID, consumerID, authID); err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteNoContent(c)
}

// DetachAuth godoc
// @Summary      Detach an auth from a consumer
// @Description  Removes the association between an auth credential and a consumer (idempotent).
// @Tags         consumers
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path  string  true  "Gateway id"   format(uuid)
// @Param        id          path  string  true  "Consumer id"  format(uuid)
// @Param        auth_id     path  string  true  "Auth id"      format(uuid)
// @Success      204         "No Content"
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/consumers/{id}/auths/{auth_id} [delete]
func (h *AssociationHandler) DetachAuth(c *fiber.Ctx) error {
	gatewayID, consumerID, authID, err := httpio.ParseConsumerAssociationID[ids.AuthKind](c, "auth_id")
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if err := h.associator.DetachAuth(c.UserContext(), gatewayID, consumerID, authID); err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteNoContent(c)
}

// AttachPolicy godoc
// @Summary      Attach a policy to a consumer
// @Description  Associates a policy with a consumer (idempotent). Editing the policy later affects every consumer it is attached to.
// @Tags         consumers
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path  string  true  "Gateway id"   format(uuid)
// @Param        id          path  string  true  "Consumer id"  format(uuid)
// @Param        policy_id   path  string  true  "Policy id"    format(uuid)
// @Success      204         "No Content"
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/consumers/{id}/policies/{policy_id} [post]
func (h *AssociationHandler) AttachPolicy(c *fiber.Ctx) error {
	gatewayID, consumerID, policyID, err := httpio.ParseConsumerAssociationID[ids.PolicyKind](c, "policy_id")
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if err := h.associator.AttachPolicy(c.UserContext(), gatewayID, consumerID, policyID); err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteNoContent(c)
}

// DetachPolicy godoc
// @Summary      Detach a policy from a consumer
// @Description  Removes the association between a policy and a consumer (idempotent).
// @Tags         consumers
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path  string  true  "Gateway id"   format(uuid)
// @Param        id          path  string  true  "Consumer id"  format(uuid)
// @Param        policy_id   path  string  true  "Policy id"    format(uuid)
// @Success      204         "No Content"
// @Failure      400         {object}  httpio.ErrorBody
// @Failure      401         {object}  httpio.ErrorBody
// @Failure      404         {object}  httpio.ErrorBody
// @Router       /v1/gateways/{gateway_id}/consumers/{id}/policies/{policy_id} [delete]
func (h *AssociationHandler) DetachPolicy(c *fiber.Ctx) error {
	gatewayID, consumerID, policyID, err := httpio.ParseConsumerAssociationID[ids.PolicyKind](c, "policy_id")
	if err != nil {
		return httpio.WriteError(c, err)
	}
	if err := h.associator.DetachPolicy(c.UserContext(), gatewayID, consumerID, policyID); err != nil {
		return httpio.WriteError(c, err)
	}
	return httpio.WriteNoContent(c)
}
