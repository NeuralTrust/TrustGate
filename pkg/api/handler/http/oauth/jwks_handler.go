package oauth

import (
	"github.com/NeuralTrust/AgentGateway/pkg/app/identity/sts"
	"github.com/gofiber/fiber/v2"
)

const JWKSPath = "/.well-known/jwks.json"

type JWKSHandler struct {
	signer sts.TokenSigner
}

func NewJWKSHandler(signer sts.TokenSigner) *JWKSHandler {
	return &JWKSHandler{signer: signer}
}

// Handle godoc
// @Summary      STS JWKS
// @Description  Public verification keys for tokens minted by the gateway's Security Token Service (downstream impersonation/delegation, RFC 8693).
// @Tags         oauth
// @Produce      json
// @Success      200  {object}  map[string]any
// @Router       /.well-known/jwks.json [get]
func (h *JWKSHandler) Handle(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(h.signer.JWKS())
}
