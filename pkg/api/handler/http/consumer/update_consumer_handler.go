package consumer

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/consumer/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/consumer/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

type UpdateConsumerHandler struct {
	updater appconsumer.Updater
}

func NewUpdateConsumerHandler(updater appconsumer.Updater) *UpdateConsumerHandler {
	return &UpdateConsumerHandler{updater: updater}
}

// Handle godoc
// @Summary      Update a consumer
// @Description  Updates an existing consumer.
// @Tags         consumers
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                         true  "Gateway id"   format(uuid)
// @Param        id          path      string                         true  "Consumer id"  format(uuid)
// @Param        body        body      request.UpdateConsumerRequest  true  "Consumer fields to update"
// @Success      200         {object}  response.ConsumerResponse
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Failure      409         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/consumers/{id} [put]
func (h *UpdateConsumerHandler) Handle(c *fiber.Ctx) error {
	gatewayID, id, err := helpers.ParseGatewayScopedID[ids.ConsumerKind](c)
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

	fallback, err := req.ToFallback()
	if err != nil {
		return helpers.WriteError(c, err)
	}
	modelPolicies, err := req.ToModelPolicies()
	if err != nil {
		return helpers.WriteError(c, err)
	}

	cons, err := h.updater.Update(c.UserContext(), appconsumer.UpdateInput{
		ID:              id,
		GatewayID:       gatewayID,
		Name:            req.Name,
		Type:            req.ToType(),
		Path:            req.Path,
		Algorithm:       req.ToAlgorithm(),
		EmbeddingConfig: req.ToEmbeddingConfig(),
		Headers:         req.Headers,
		Active:          req.Active,
		Fallback:        fallback,
		ModelPolicies:   modelPolicies,
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, response.FromConsumer(cons))
}
