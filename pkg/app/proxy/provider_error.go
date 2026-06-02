package proxy

import "github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"

func responseCarriesProviderError(resp *ProviderResponse) bool {
	if resp == nil || len(resp.Body) == 0 {
		return false
	}
	return adapter.BodyCarriesRetryableError(resp.Body)
}
