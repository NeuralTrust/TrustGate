package helpers

import (
	"context"
	"net/url"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/gofiber/fiber/v2"
)

func GetQueryParams(c *fiber.Ctx) url.Values {
	queryParams := make(url.Values)
	c.Request().URI().QueryArgs().VisitAll(func(k, v []byte) {
		queryParams.Add(string(k), string(v))
	})
	return queryParams
}

func GetPathParamsFromContext(ctx context.Context) map[string]string {
	if pathParams := ctx.Value(common.PathParamsKey); pathParams != nil {
		if params, ok := pathParams.(map[string]string); ok {
			return params
		}
	}
	return nil
}

func ReplacePathParams(path string, pathParams map[string]string) string {
	result := path
	for paramName, paramValue := range pathParams {
		paramPlaceholder := "{" + paramName + "}"
		if strings.Contains(result, paramPlaceholder) {
			result = strings.ReplaceAll(result, paramPlaceholder, paramValue)
		}
	}
	return result
}
