package http

import (
	"github.com/NeuralTrust/AgentGateway/pkg/version"
	"github.com/gofiber/fiber/v2"
)

type VersionHandler struct{}

func NewVersionHandler() *VersionHandler { return &VersionHandler{} }

func (h *VersionHandler) Handle(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(version.GetInfo())
}
