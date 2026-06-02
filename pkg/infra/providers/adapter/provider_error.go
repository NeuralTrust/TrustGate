package adapter

import (
	"encoding/json"
	"strings"
)

// retryableErrorMarkers are provider error codes/types that indicate a
// transient condition worth failing over for: overload, rate limiting and quota
// exhaustion, plus generic transient server errors. Matching is case-insensitive
// substring over the error's type/code/message.
var retryableErrorMarkers = []string{
	"overloaded",
	"rate_limit",
	"rate limit",
	"insufficient_quota",
	"service_unavailable",
	"server_error",
	"server_overloaded",
	"try again",
	"temporarily unavailable",
}

// providerErrorEnvelope captures the common shape of provider error payloads
// across the OpenAI/Anthropic/Gemini families: a nested "error" object (or a
// top-level error string) with a type/code/status/message.
type providerErrorEnvelope struct {
	Error *providerErrorBody `json:"error"`
}

type providerErrorBody struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

// BodyCarriesRetryableError reports whether a JSON body embeds a provider error
// whose code/type/message marks a transient, retryable condition. It is used to
// honor the provider_error fallback trigger for backends that return such errors
// inside an otherwise-2xx response. A body without a recognizable error envelope
// returns false.
func BodyCarriesRetryableError(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var env providerErrorEnvelope
	if err := json.Unmarshal(body, &env); err != nil || env.Error == nil {
		return false
	}
	haystack := strings.ToLower(strings.Join([]string{
		env.Error.Type,
		env.Error.Code,
		env.Error.Status,
		env.Error.Message,
	}, " "))
	for _, marker := range retryableErrorMarkers {
		if strings.Contains(haystack, marker) {
			return true
		}
	}
	return false
}
