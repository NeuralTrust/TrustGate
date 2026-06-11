package role

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	approle "github.com/NeuralTrust/AgentGateway/pkg/app/role"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type AssociationHandler struct {
	associator approle.Associator
}

func NewAssociationHandler(associator approle.Associator) *AssociationHandler {
	return &AssociationHandler{associator: associator}
}

// AttachRegistry godoc
// @Summary      Attach a registry to a role
// @Description  Associates a registry with a role (idempotent).
// @Tags         roles
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id   path  string  true  "Gateway id"   format(uuid)
// @Param        role_id      path  string  true  "Role id"      format(uuid)
// @Param        registry_id  path  string  true  "Registry id"  format(uuid)
// @Success      204          "No Content"
// @Failure      400          {object}  helpers.ErrorBody
// @Failure      401          {object}  helpers.ErrorBody
// @Failure      404          {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/roles/{role_id}/registries/{registry_id} [post]
func (h *AssociationHandler) AttachRegistry(c *fiber.Ctx) error {
	gatewayID, roleID, registryID, err := parseAssociationIDs(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	if err := h.associator.AttachRegistry(c.UserContext(), gatewayID, roleID, registryID); err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteNoContent(c)
}

// DetachRegistry godoc
// @Summary      Detach a registry from a role
// @Description  Removes the association between a registry and a role (idempotent).
// @Tags         roles
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id   path  string  true  "Gateway id"   format(uuid)
// @Param        role_id      path  string  true  "Role id"      format(uuid)
// @Param        registry_id  path  string  true  "Registry id"  format(uuid)
// @Success      204          "No Content"
// @Failure      400          {object}  helpers.ErrorBody
// @Failure      401          {object}  helpers.ErrorBody
// @Failure      404          {object}  helpers.ErrorBody
// @Failure      409          {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/roles/{role_id}/registries/{registry_id} [delete]
func (h *AssociationHandler) DetachRegistry(c *fiber.Ctx) error {
	gatewayID, roleID, registryID, err := parseAssociationIDs(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	if err := h.associator.DetachRegistry(c.UserContext(), gatewayID, roleID, registryID); err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteNoContent(c)
}

func parseAssociationIDs(c *fiber.Ctx) (ids.GatewayID, ids.RoleID, ids.RegistryID, error) {
	gatewayID, err := helpers.ParseGatewayID(c)
	if err != nil {
		return ids.GatewayID{}, ids.RoleID{}, ids.RegistryID{}, err
	}
	roleID, err := helpers.ParseUUIDParam[ids.RoleKind](c, "role_id")
	if err != nil {
		return ids.GatewayID{}, ids.RoleID{}, ids.RegistryID{}, err
	}
	registryID, err := helpers.ParseUUIDParam[ids.RegistryKind](c, "registry_id")
	if err != nil {
		return ids.GatewayID{}, ids.RoleID{}, ids.RegistryID{}, err
	}
	return gatewayID, roleID, registryID, nil
}
