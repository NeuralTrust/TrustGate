package middleware

import (
	"context"
	"slices"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/apikey"
	"github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/app/routing"
	"github.com/gofiber/fiber/v2"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// moved to common.TrustgateAuthHeader

type authMiddleware struct {
	logger        *logrus.Logger
	keyFinder     apikey.Finder
	gatewayFinder gateway.DataFinder
	ruleMatcher   routing.RuleMatcher
}

func NewAuthMiddleware(
	logger *logrus.Logger,
	keyFinder apikey.Finder,
	gatewayFinder gateway.DataFinder,
	ruleMatcher routing.RuleMatcher,
) Middleware {
	return &authMiddleware{
		logger:        logger,
		keyFinder:     keyFinder,
		gatewayFinder: gatewayFinder,
		ruleMatcher:   ruleMatcher,
	}
}

func (m *authMiddleware) Middleware() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		m.setLatencyStart(ctx)
		apiKey := m.getAPIKeyHeader(ctx)
		if apiKey == "" {
			m.logger.Debug("no api key provided")
			return m.respondWithError(ctx, fiber.StatusUnauthorized, "API key required")
		}
		key, err := m.keyFinder.Find(ctx.Context(), apiKey)
		if err != nil {
			m.logger.WithError(err).Error("error retrieving apikey")
			return m.respondWithError(ctx, fiber.StatusUnauthorized, "invalid API key")
		}

		if !key.IsValid() {
			m.logger.Debug("invalid API key")
			return m.respondWithError(ctx, fiber.StatusUnauthorized, "invalid API key")
		}

		if key.Subject == uuid.Nil {
			m.logger.Debug("API key has no subject")
			return m.respondWithError(ctx, fiber.StatusUnauthorized, "invalid API key")
		}

		gatewayData, err := m.gatewayFinder.Find(ctx.Context(), key.Subject)
		if err != nil {
			m.logger.WithError(err).Error("failed to fetch gateway data.")
			return m.respondWithError(ctx, fiber.StatusInternalServerError, "failed to fetch gateway data")
		}

		m.attachRequestContext(ctx, apiKey, key.ID.String(), key.Subject.String(), gatewayData)

		matchingRule, pathParams := m.ruleMatcher.MatchRule(ctx.Path(), ctx.Method(), gatewayData.Rules)
		if matchingRule == nil {
			m.logger.WithFields(logrus.Fields{
				"path":   ctx.Path(),
				"method": ctx.Method(),
			}).Debug("no matching rule found")
			return m.respondWithError(ctx, fiber.StatusNotFound, "no matching rule found")
		}

		if len(pathParams) > 0 {
			ctx.Locals(common.PathParamsKey, pathParams)
			c := context.WithValue(ctx.Context(), common.PathParamsKey, pathParams)
			ctx.SetUserContext(c)
		}

		if len(key.Policies) > 0 {
			ruleUUID, err := uuid.Parse(matchingRule.ID)
			if err != nil {
				m.logger.WithError(err).Warn("invalid rule ID format for policy validation")
				return m.respondWithError(ctx, fiber.StatusUnauthorized, "unauthorized")
			}

			if !slices.Contains(key.Policies, ruleUUID) {
				return m.respondWithError(ctx, fiber.StatusUnauthorized, "unauthorized")
			}
		}

		m.setRuleContext(ctx, matchingRule)
		return ctx.Next()
	}
}

func (m *authMiddleware) getAPIKeyHeader(ctx *fiber.Ctx) string {
	return ctx.Get(common.TrustgateAuthHeader)
}

func (m *authMiddleware) respondWithError(ctx *fiber.Ctx, status int, message string) error {
	return ctx.Status(status).JSON(fiber.Map{"error": message})
}

func (m *authMiddleware) setLatencyStart(ctx *fiber.Ctx) {
	now := time.Now()
	ctx.Locals(common.LatencyContextKey, now)
	c := context.WithValue(ctx.Context(), common.LatencyContextKey, now)
	ctx.SetUserContext(c)
}

func (m *authMiddleware) attachRequestContext(
	ctx *fiber.Ctx,
	apiKey string,
	apiKeyID string,
	gatewayID string,
	gatewayData *types.GatewayData) {
	metadata := map[string]interface{}{
		string(common.ApiKeyContextKey):  apiKey,
		string(common.GatewayContextKey): gatewayID,
	}

	// Fiber locals
	ctx.Locals(common.ApiKeyContextKey, apiKey)
	ctx.Locals(common.ApiKeyIdContextKey, apiKeyID)
	ctx.Locals(common.MetadataKey, metadata)
	ctx.Locals(common.GatewayContextKey, gatewayID)
	ctx.Locals(string(common.GatewayDataContextKey), gatewayData)

	// User context
	c := context.WithValue(ctx.Context(), common.ApiKeyContextKey, apiKey)
	c = context.WithValue(c, common.MetadataKey, metadata)
	c = context.WithValue(c, common.ApiKeyIdContextKey, apiKeyID)
	c = context.WithValue(c, common.GatewayContextKey, gatewayID)
	//nolint
	c = context.WithValue(c, string(common.GatewayDataContextKey), gatewayData)
	ctx.SetUserContext(c)
}

func (m *authMiddleware) setRuleContext(ctx *fiber.Ctx, rule *types.ForwardingRule) {
	ctx.Set(RouteIDKey, rule.ID)
	ctx.Set(ServiceIDKey, rule.ServiceID)

	ctx.Locals(string(common.MatchedRuleContextKey), rule)
	c := context.WithValue(ctx.Context(), common.MatchedRuleContextKey, rule)
	ctx.SetUserContext(c)
}
