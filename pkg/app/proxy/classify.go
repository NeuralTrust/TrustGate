package proxy

import "net/http"

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
