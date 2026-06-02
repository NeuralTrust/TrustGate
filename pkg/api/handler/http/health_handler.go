package http

import (
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/version"
	"github.com/gofiber/fiber/v2"
)

type HealthHandler struct{}

func NewHealthHandler() *HealthHandler { return &HealthHandler{} }

// Liveness godoc
// @Summary      Liveness probe
// @Description  Reports whether the process is alive.
// @Tags         system
// @Produce      json
// @Success      200  {object}  map[string]string
// @Router       /healthz [get]
func (h *HealthHandler) Liveness(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "healthy",
		"version": version.Version,
		"time":    time.Now().Format(time.RFC3339),
	})
}

// Readiness godoc
// @Summary      Readiness probe
// @Description  Reports whether the process is ready to serve traffic.
// @Tags         system
// @Produce      json
// @Success      200  {object}  map[string]string
// @Router       /readyz [get]
func (h *HealthHandler) Readiness(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "ready",
		"version": version.Version,
		"time":    time.Now().Format(time.RFC3339),
	})
}
