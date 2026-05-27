package http

import (
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/version"
	"github.com/gofiber/fiber/v2"
)

type HealthHandler struct{}

func NewHealthHandler() *HealthHandler { return &HealthHandler{} }

func (h *HealthHandler) Liveness(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "healthy",
		"version": version.Version,
		"time":    time.Now().Format(time.RFC3339),
	})
}

func (h *HealthHandler) Readiness(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "ready",
		"version": version.Version,
		"time":    time.Now().Format(time.RFC3339),
	})
}
