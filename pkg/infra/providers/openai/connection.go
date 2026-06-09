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
	endpointURL, err := c.resolveModelsURL(config)
	if err != nil {
		return providers.ProbeResult{
			OK:      false,
			Stage:   providers.StageProvider,
			Message: err.Error(),
		}
	}
	return providers.RunBearerGETProbe(ctx, providers.ProviderOpenAI, endpointURL, config.Credentials.ApiKey)
}

func (c *client) resolveModelsURL(config *providers.Config) (string, error) {
	opts, err := providers.DecodeOpenAIOptions(config.Options)
	if err != nil {
		return "", err
	}
	base := strings.TrimRight(opts.BaseURL, "/")
	if base != "" {
		return base + modelsPath, nil
	}
	return modelsURL, nil
}
