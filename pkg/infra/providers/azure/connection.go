package azure

import (
	"context"
	"fmt"
	"net/http"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
)

func (c *client) TestConnection(ctx context.Context, config *providers.Config) providers.ProbeResult {
	if config.Credentials.Azure == nil || config.Credentials.Azure.Endpoint == "" {
		return providers.ProbeResult{
			OK:      false,
			Stage:   providers.StageConnectivity,
			Message: "azure endpoint is required",
		}
	}

	token, err := c.getToken(ctx, config)
	if err != nil {
		return providers.ProbeResult{
			OK:      false,
			Stage:   providers.StageAuthentication,
			Message: err.Error(),
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.buildModelsURL(config), nil)
	if err != nil {
		return providers.ProbeResult{OK: false, Stage: providers.StageConnectivity, Message: err.Error()}
	}
	c.applyAuthHeader(req, config.Credentials.Azure.UseIdentity, token)
	return providers.RunHTTPProbe(providers.ProviderAzure, req)
}

func (c *client) buildModelsURL(config *providers.Config) string {
	apiVersion := defaultAPIVersion
	if config.Credentials.Azure.ApiVersion != "" {
		apiVersion = config.Credentials.Azure.ApiVersion
	}
	return fmt.Sprintf("%s/openai/models?api-version=%s", config.Credentials.Azure.Endpoint, apiVersion)
}
