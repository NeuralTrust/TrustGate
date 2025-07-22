package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/version"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type getVersionHandler struct {
	logger *logrus.Logger
}

func NewGetVersionHandler(logger *logrus.Logger) Handler {
	return &getVersionHandler{
		logger: logger,
	}
}

// Handle @Summary Get AI-Gateway Version
// @Description Returns the current version of the AI-Gateway
// @Tags Version
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{} "Version information"
// @Router /api/v1/version [get]
func (h *getVersionHandler) Handle(c *fiber.Ctx) error {
	versionInfo := version.GetInfo()
	return c.Status(fiber.StatusOK).JSON(versionInfo)
}
