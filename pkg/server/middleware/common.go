package middleware

import (
	"context"
	"net/url"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/sirupsen/logrus"
)

func GetMatchedRule(ctx context.Context, logger *logrus.Logger) *types.ForwardingRuleDTO {
	rule, ok := ctx.Value(string(common.MatchedRuleContextKey)).(*types.ForwardingRuleDTO)
	if !ok || rule == nil {
		logger.Error("failed to get matched rule from context")
		return &types.ForwardingRuleDTO{}
	}
	return rule
}

// GetMatchedRuleFromFiber retrieves the matched rule from fiber Locals (canonical in production) or context.
func GetMatchedRuleFromFiber(c *fiber.Ctx, logger *logrus.Logger) *types.ForwardingRuleDTO {
	if rule, ok := c.Locals(string(common.MatchedRuleContextKey)).(*types.ForwardingRuleDTO); ok && rule != nil {
		return rule
	}
	return GetMatchedRule(c.Context(), logger)
}

func GetGatewayData(c *fiber.Ctx) (*types.GatewayData, bool) {
	data, ok := c.Locals(string(common.GatewayDataContextKey)).(*types.GatewayData)
	return data, ok
}

func GetGatewayID(c *fiber.Ctx) (string, bool) {
	id, ok := c.Locals(common.GatewayContextKey).(string)
	if !ok || id == "" {
		return "", false
	}
	return id, true
}

func GetQueryParams(c *fiber.Ctx) url.Values {
	queryParams := make(url.Values)
	c.Request().URI().QueryArgs().VisitAll(func(k, v []byte) {
		queryParams.Set(string(k), string(v))
	})
	return queryParams
}
