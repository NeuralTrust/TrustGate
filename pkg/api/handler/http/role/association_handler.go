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
