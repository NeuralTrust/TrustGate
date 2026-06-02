package proxy

import (
	"net/http"

	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
)

// Outcome is the failover classification of a single backend attempt.
type Outcome int

const (
	// OutcomeSuccess is a committed result (2xx, or a streaming response that
	// already opened): relay it and stop.
	OutcomeSuccess Outcome = iota
	// OutcomeRetryable is a transient failure (transport/timeout, 5xx/429/408,
	// or an enabled additive trigger): try the next attempt/backend.
	OutcomeRetryable
	// OutcomeTerminal is a non-retryable client error (4xx other than 429):
	// relay verbatim without failover.
	OutcomeTerminal
)

// String returns the lowercase label used in metrics events.
func (o Outcome) String() string {
	switch o {
	case OutcomeSuccess:
		return "success"
	case OutcomeRetryable:
		return "retryable"
	case OutcomeTerminal:
		return "terminal"
	default:
		return "unknown"
	}
}

// fallbackTriggers is the resolved additive trigger set for a request, derived
// from the consumer's fallback config. The always-on transient set (transport,
// timeout, 5xx, 429, 408) is handled unconditionally; these gate the optional
// provider_error / plugin_rejection paths.
type fallbackTriggers struct {
	providerError   bool
	pluginRejection bool
}

// triggersFrom resolves the additive trigger set from a (possibly nil/disabled)
// fallback config.
func triggersFrom(fb *consumerdomain.Fallback) fallbackTriggers {
	if fb == nil || !fb.Enabled {
		return fallbackTriggers{}
	}
	return fallbackTriggers{
		providerError:   fb.HasTrigger(consumerdomain.TriggerProviderError),
		pluginRejection: fb.HasTrigger(consumerdomain.TriggerPluginReject),
	}
}

// classifyOutcome maps a backend attempt (response + transport error) to a
// failover outcome. Transport errors and the transient status set are always
// retryable; a committed stream and 2xx are success; provider_error (a 2xx body
// carrying a provider failure code) is retryable only when the trigger is
// enabled; every other 4xx is terminal.
func classifyOutcome(resp *ProviderResponse, err error, triggers fallbackTriggers) Outcome {
	if err != nil {
		return OutcomeRetryable
	}
	if resp == nil {
		return OutcomeRetryable
	}
	if resp.Stream != nil {
		return OutcomeSuccess
	}
	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		if triggers.providerError && responseCarriesProviderError(resp) {
			return OutcomeRetryable
		}
		return OutcomeSuccess
	}
	if backendFailureStatus(resp.StatusCode) {
		return OutcomeRetryable
	}
	return OutcomeTerminal
}

// backendFailureStatus reports whether an HTTP status returned by a backend must
// count as a health failure for the passive breaker. 5xx, 429 (rate limit) and
// 408 (request timeout) signal the backend is unhealthy or overloaded; every
// other status (including 4xx client errors, which are the caller's fault) does
// not and must not trip the breaker.
func backendFailureStatus(statusCode int) bool {
	if statusCode >= http.StatusInternalServerError {
		return true
	}
	switch statusCode {
	case http.StatusTooManyRequests, http.StatusRequestTimeout:
		return true
	default:
		return false
	}
}
