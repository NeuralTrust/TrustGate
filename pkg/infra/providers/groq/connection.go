package groq

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
)

const modelsURL = "https://api.groq.com/openai/v1/models"

func (c *client) TestConnection(ctx context.Context, config *providers.Config) providers.ProbeResult {
	return providers.RunBearerGETProbe(ctx, providers.ProviderGroq, modelsURL, config.Credentials.ApiKey)
}
