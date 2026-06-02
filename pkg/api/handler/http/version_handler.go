package http

import (
	"github.com/NeuralTrust/AgentGateway/pkg/version"
	"github.com/gofiber/fiber/v2"
)

type VersionHandler struct{}

func NewVersionHandler() *VersionHandler { return &VersionHandler{} }

// Handle godoc
// @Summary      Build version
// @Description  Returns build/version information for the running binary.
// @Tags         system
// @Produce      json
// @Success      200  {object}  version.Info
// @Router       /__/version [get]
func (h *VersionHandler) Handle(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(version.GetInfo())
}
