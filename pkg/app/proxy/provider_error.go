package proxy

import "github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"

// responseCarriesProviderError reports whether a 2xx backend response body
// carries a provider-level error code that should be treated as retryable when
// the provider_error fallback trigger is enabled (e.g. an "overloaded" or
// "rate_limit_exceeded" code embedded in an otherwise-200 payload).
//
// It delegates the provider-specific body inspection to the adapter layer.
func responseCarriesProviderError(resp *ProviderResponse) bool {
	if resp == nil || len(resp.Body) == 0 {
		return false
	}
	return adapter.BodyCarriesRetryableError(resp.Body)
}
