package consumer

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/consumer/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/consumer/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/gofiber/fiber/v2"
)

type UpdateConsumerHandler struct {
	updater appconsumer.Updater
}

func NewUpdateConsumerHandler(updater appconsumer.Updater) *UpdateConsumerHandler {
	return &UpdateConsumerHandler{updater: updater}
}

func (h *UpdateConsumerHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}

	var req request.UpdateConsumerRequest
	if err := c.BodyParser(&req); err != nil {
		return helpers.WriteError(c, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation))
	}
	if err := req.Validate(); err != nil {
		return helpers.WriteError(c, err)
	}

	backendIDs, err := req.ToBackendIDs()
	if err != nil {
		return helpers.WriteError(c, err)
	}
	policyIDs, err := req.ToPolicyIDs()
	if err != nil {
		return helpers.WriteError(c, err)
	}
	authIDs, err := req.ToAuthIDs()
	if err != nil {
		return helpers.WriteError(c, err)
	}
	fallback, err := req.ToFallback()
	if err != nil {
		return helpers.WriteError(c, err)
	}

	cons, err := h.updater.Update(c.UserContext(), appconsumer.UpdateInput{
		ID:              id,
		GatewayID:       gatewayID,
		Name:            req.Name,
		Type:            req.ToType(),
		Path:            req.Path,
		Algorithm:       req.Algorithm,
		EmbeddingConfig: req.ToEmbeddingConfig(),
		Headers:         req.Headers,
		Active:          req.Active,
		BackendIDs:      backendIDs,
		PolicyIDs:       policyIDs,
		AuthIDs:         authIDs,
		Fallback:        fallback,
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromConsumer(cons))
}
