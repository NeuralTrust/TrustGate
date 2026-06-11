package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"

	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
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
	http5xx         bool
	http429         bool
	timeout         bool
	providerError   bool
	pluginRejection bool
}

func triggersFrom(fb *consumerdomain.Fallback) fallbackTriggers {
	if fb == nil || !fb.Enabled {
		return fallbackTriggers{}
	}
	return fallbackTriggers{
		http5xx:         fb.HasTrigger(consumerdomain.TriggerHTTP5xx),
		http429:         fb.HasTrigger(consumerdomain.TriggerHTTP429),
		timeout:         fb.HasTrigger(consumerdomain.TriggerTimeout),
		providerError:   fb.HasTrigger(consumerdomain.TriggerProviderError),
		pluginRejection: fb.HasTrigger(consumerdomain.TriggerPluginReject),
	}
}

// failureKind classifies a retryable failure into the fallback trigger class
// that must be enabled for the failure to advance into the fallback chain.
type failureKind int

const (
	failureNone failureKind = iota
	failureHTTP5xx
	failureHTTP429
	failureTimeout
	failureProviderError
	failurePluginRejection
)

// classifyFailure maps a retryable outcome to its trigger class. Transport
// errors that are not timeouts count as http_5xx: the upstream is unreachable,
// which is operationally equivalent to a server-side failure.
func classifyFailure(resp *ProviderResponse, err error) failureKind {
	if err != nil {
		if isTimeoutError(err) {
			return failureTimeout
		}
		return failureHTTP5xx
	}
	if resp == nil {
		return failureHTTP5xx
	}
	switch {
	case resp.StatusCode == http.StatusRequestTimeout:
		return failureTimeout
	case resp.StatusCode == http.StatusTooManyRequests:
		return failureHTTP429
	case resp.StatusCode >= http.StatusInternalServerError:
		return failureHTTP5xx
	case resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices:
		return failureProviderError
	default:
		return failureNone
	}
}

func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// allowsFallback reports whether the configured triggers permit advancing into
// the fallback chain after a failure of the given kind.
func (t fallbackTriggers) allowsFallback(kind failureKind) bool {
	switch kind {
	case failureHTTP5xx:
		return t.http5xx
	case failureHTTP429:
		return t.http429
	case failureTimeout:
		return t.timeout
	case failureProviderError:
		return t.providerError
	case failurePluginRejection:
		return t.pluginRejection
	default:
		return false
	}
}

func classifyOutcome(resp *ProviderResponse, err error, triggers fallbackTriggers) Outcome {
	if err != nil {
		if errors.Is(err, ErrModelNotAllowed) ||
			errors.Is(err, ErrInvalidRequestPayload) ||
			errors.Is(err, registrydomain.ErrCredentialAcquisition) {
			return OutcomeTerminal
		}
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
