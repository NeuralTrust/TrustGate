package proxy

import (
	"net/http"

	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
)

type Outcome int

const (
	OutcomeSuccess Outcome = iota

	OutcomeRetryable

	OutcomeTerminal
)

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

type fallbackTriggers struct {
	providerError   bool
	pluginRejection bool
}

func triggersFrom(fb *consumerdomain.Fallback) fallbackTriggers {
	if fb == nil || !fb.Enabled {
		return fallbackTriggers{}
	}
	return fallbackTriggers{
		providerError:   fb.HasTrigger(consumerdomain.TriggerProviderError),
		pluginRejection: fb.HasTrigger(consumerdomain.TriggerPluginReject),
	}
}

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
