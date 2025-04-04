package middleware

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/gofiber/fiber/v2"

	"github.com/sirupsen/logrus"
)

type fingerPrintMiddleware struct {
	logger  *logrus.Logger
	manager fingerprint.Tracker
}

func NewFingerPrintMiddleware(
	logger *logrus.Logger,
	manager fingerprint.Tracker,
) Middleware {
	return &fingerPrintMiddleware{
		logger:  logger,
		manager: manager,
	}
}

func (m *fingerPrintMiddleware) Middleware() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		fingerPrint := m.manager.MakeFingerprint(ctx)
		ctx.Locals(common.FingerprintIdContextKey, fingerPrint.ID())
		c := context.WithValue(ctx.Context(), common.FingerprintIdContextKey, fingerPrint.ID())
		ctx.SetUserContext(c)
		return ctx.Next()
	}
}
