package openaicompat

import (
	"context"
	"net/http"
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
)

const modelsPath = "/models"

// TestConnection probes the upstream with a Bearer GET to {base_url}/models,
// the de-facto discovery endpoint exposed by OpenAI-compatible servers. Any
// configured custom headers are applied to the probe as well.
func (c *client) TestConnection(ctx context.Context, config *providers.Config) providers.ProbeResult {
	opts, err := providers.DecodeOpenAICompatibleOptions(config.Options)
	if err != nil {
		return providers.ProbeResult{
			OK:      false,
			Stage:   providers.StageProvider,
			Message: err.Error(),
		}
	}
	base := strings.TrimRight(opts.BaseURL, "/")
	return providers.RunAPIKeyGETProbe(
		ctx,
		providers.ProviderOpenAICompatible,
		base+modelsPath,
		config.Credentials.ApiKey,
		func(req *http.Request, key string) {
			req.Header.Set("Authorization", "Bearer "+key)
			for k, v := range opts.Headers {
				if k == "" {
					continue
				}
				req.Header.Set(k, v)
			}
		},
	)
}
