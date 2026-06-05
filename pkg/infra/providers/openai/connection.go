package openai

import (
	"context"
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
)

const (
	modelsURL  = "https://api.openai.com/v1/models"
	modelsPath = "/models"
)

func (c *client) TestConnection(ctx context.Context, config *providers.Config) providers.ProbeResult {
	return providers.RunBearerGETProbe(ctx, providers.ProviderOpenAI, c.resolveModelsURL(config), config.Credentials.ApiKey)
}

func (c *client) resolveModelsURL(config *providers.Config) string {
	base := strings.TrimRight(parseOptions(config).BaseURL, "/")
	if base != "" {
		return base + modelsPath
	}
	return modelsURL
}
