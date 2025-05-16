package http

import (
	"github.com/NeuralTrust/TrustGate/pkg/plugins"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type listPluginsHandler struct {
	logger *logrus.Logger
}

func NewListPluginsHandler(logger *logrus.Logger) Handler {
	return &listPluginsHandler{
		logger: logger,
	}
}

// Handle @Summary Get Available Plugins
// @Description Returns the list of available plugins
// @Tags Plugins
// @Accept json
// @Produce json
// @Success 200 {array} plugins.PluginDefinition "List of plugins"
// @Router /api/v1/plugins [get]
func (h *listPluginsHandler) Handle(c *fiber.Ctx) error {
	h.logger.Info("Handling request to list plugins")

	return c.Status(fiber.StatusOK).JSON(plugins.PluginList)
}
