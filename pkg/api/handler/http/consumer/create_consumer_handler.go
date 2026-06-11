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

type CreateConsumerHandler struct {
	creator appconsumer.Creator
}

func NewCreateConsumerHandler(creator appconsumer.Creator) *CreateConsumerHandler {
	return &CreateConsumerHandler{creator: creator}
}

// Handle godoc
// @Summary      Create a consumer
// @Description  Creates a new consumer in a gateway.
// @Tags         consumers
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        gateway_id  path      string                         true  "Gateway id"  format(uuid)
// @Param        body        body      request.CreateConsumerRequest  true  "Consumer to create"
// @Success      201         {object}  response.ConsumerResponse
// @Failure      400         {object}  helpers.ErrorBody
// @Failure      401         {object}  helpers.ErrorBody
// @Failure      404         {object}  helpers.ErrorBody
// @Failure      409         {object}  helpers.ErrorBody
// @Router       /v1/gateways/{gateway_id}/consumers [post]
func (h *CreateConsumerHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := helpers.ParseGatewayID(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}

	var req request.CreateConsumerRequest
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
	lbConfig, err := req.ToLBConfig()
	if err != nil {
		return helpers.WriteError(c, err)
	}
	registryIDs, modelPolicies, err := req.ToRegistryBindings()
	if err != nil {
		return helpers.WriteError(c, err)
	}
	roleIDs, err := req.ToRoleIDs()
	if err != nil {
		return helpers.WriteError(c, err)
	}

	cons, err := h.creator.Create(c.UserContext(), appconsumer.CreateInput{
		GatewayID:     gatewayID,
		Name:          req.Name,
		Type:          req.ToType(),
		RoutingMode:   req.ToRoutingMode(),
		LBConfig:      lbConfig,
		Headers:       req.Headers,
		Active:        req.Active,
		Fallback:      fallback,
		RegistryIDs:   registryIDs,
		RoleIDs:       roleIDs,
		ModelPolicies: modelPolicies,
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteCreated(c, response.FromConsumer(cons))
}
