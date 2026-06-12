package oauth

import (
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/helpers"
	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

const WellKnownProtectedResourcePath = "/.well-known/oauth-protected-resource"

type ProtectedResourceHandler struct {
	metadata appoauth.MetadataService
}

func NewProtectedResourceHandler(metadata appoauth.MetadataService) *ProtectedResourceHandler {
	return &ProtectedResourceHandler{metadata: metadata}
}

func (h *ProtectedResourceHandler) Handle(c *fiber.Ctx) error {
	resource := c.BaseURL()
	if suffix := strings.Trim(c.Params("*"), "/"); suffix != "" {
		resource += "/" + suffix
	}
	meta, err := h.metadata.ProtectedResource(c.UserContext(), c.BaseURL(), resource)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, meta)
}
