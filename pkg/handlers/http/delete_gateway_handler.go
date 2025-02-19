package http

import (
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/database"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

type deleteGatewayHandler struct {
	logger *logrus.Logger
	repo   *database.Repository
}

func NewDeleteGatewayHandler(logger *logrus.Logger, repo *database.Repository) Handler {
	return &deleteGatewayHandler{
		logger: logger,
		repo:   repo,
	}
}

func (s *deleteGatewayHandler) Handle(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id is required"})
	}
	if err := s.repo.DeleteGateway(id); err != nil {
		s.logger.WithError(err).Error("Failed to delete gateway")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.SendStatus(http.StatusNoContent)
}
