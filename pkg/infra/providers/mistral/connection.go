package mistral

import (
	"context"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
)

const modelsURL = "https://api.mistral.ai/v1/models"

func (c *client) TestConnection(ctx context.Context, config *providers.Config) providers.ProbeResult {
	return providers.RunBearerGETProbe(ctx, providers.ProviderMistral, modelsURL, config.Credentials.ApiKey)
}
