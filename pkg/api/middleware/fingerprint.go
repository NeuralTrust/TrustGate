package middleware

import (
	"context"

	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/fingerprint"
	"github.com/gofiber/fiber/v2"
)

type FingerPrintMiddleware struct {
	tracker fingerprint.Tracker
}

func NewFingerPrintMiddleware(tracker fingerprint.Tracker) *FingerPrintMiddleware {
	return &FingerPrintMiddleware{tracker: tracker}
}

func (m *FingerPrintMiddleware) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		id := fingerprint.CompactID(m.tracker.MakeFingerprint(c).ID())
		c.Locals(string(infracontext.FingerprintIDContextKey), id)
		ctx := context.WithValue(c.UserContext(), infracontext.FingerprintIDContextKey, id)
		c.SetUserContext(ctx)
		return c.Next()
	}
}
