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

func (h *JWKSHandler) Handle(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(h.signer.JWKS())
}
