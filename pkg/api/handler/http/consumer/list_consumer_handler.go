package consumer

import (
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/consumer/request"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/consumer/response"
	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/gofiber/fiber/v2"
)

type ListConsumerHandler struct {
	finder appconsumer.Finder
}

func NewListConsumerHandler(finder appconsumer.Finder) *ListConsumerHandler {
	return &ListConsumerHandler{finder: finder}
}

func (h *ListConsumerHandler) Handle(c *fiber.Ctx) error {
	gatewayID, err := helpers.ParseUUIDParam(c, "gateway_id")
	if err != nil {
		return helpers.WriteError(c, err)
	}
	page, err := helpers.ParsePage(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	size, err := helpers.ParseSize(c)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	req := request.ListConsumerRequest{
		Name: c.Query("name"),
		Page: page,
		Size: size,
	}

	items, total, err := h.finder.List(c.UserContext(), domain.ListFilter{
		GatewayID:    gatewayID,
		NameContains: req.Name,
		Page:         req.Page,
		Size:         req.Size,
	})
	if err != nil {
		return helpers.WriteError(c, err)
	}

	out := response.ListConsumerResponse{
		Items: make([]response.ConsumerResponse, 0, len(items)),
		Page:  req.Page,
		Size:  req.Size,
		Total: total,
	}
	for _, cons := range items {
		out.Items = append(out.Items, response.FromConsumer(cons))
	}
	return helpers.WriteOK(c, out)
}
