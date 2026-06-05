package anthropic

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
)

const modelsURL = "https://api.anthropic.com/v1/models"

func (c *client) TestConnection(ctx context.Context, config *providers.Config) providers.ProbeResult {
	return providers.RunAPIKeyGETProbe(ctx, providers.ProviderAnthropic, modelsURL, config.Credentials.ApiKey, c.setHeaders)
}
