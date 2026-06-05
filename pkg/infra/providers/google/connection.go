package google

import (
	"context"
	"net/http"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
)

func (c *client) TestConnection(ctx context.Context, config *providers.Config) providers.ProbeResult {
	return providers.RunAPIKeyGETProbe(ctx, providers.ProviderGoogle, geminiBaseURL, config.Credentials.ApiKey, setAPIKeyHeader)
}

func setAPIKeyHeader(req *http.Request, apiKey string) {
	req.Header.Set("x-goog-api-key", apiKey)
}
