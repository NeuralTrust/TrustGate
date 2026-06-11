package registry

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ErrCredentialAcquisition marks failures obtaining provider credentials
// (e.g. an expired Azure client secret rejected by the identity provider).
// These are configuration errors: retrying cannot fix them, and the identity
// provider's response must never be relayed to the client because it carries
// tenant/app identifiers.
var ErrCredentialAcquisition = errors.New("provider credential acquisition failed")

// BackendError represents a non-2xx response received from a backend target
// (the upstream LLM provider). It carries the status code and raw body so the
// proxy can relay the backend's error to the client verbatim.
type BackendError struct {
	StatusCode int
	Body       []byte
	// RetryAfter contains the backend Retry-After header when present.
	RetryAfter string
}

func (e *BackendError) Error() string {
	return fmt.Sprintf("backend responded with status %d", e.StatusCode)
}

func NewBackendError(statusCode int, body []byte) *BackendError {
	return &BackendError{StatusCode: statusCode, Body: body}
}

// NewBackendHTTPError builds a BackendError preserving relevant backend
// response headers used by the standard error passthrough path.
func NewBackendHTTPError(statusCode int, body []byte, headers http.Header) *BackendError {
	be := NewBackendError(statusCode, body)
	if headers != nil {
		be.RetryAfter = strings.TrimSpace(headers.Get("Retry-After"))
	}
	return be
}

// PassthroughHeaders returns safe headers for backend error passthrough to the
// client.
func (e *BackendError) PassthroughHeaders() map[string][]string {
	headers := map[string][]string{
		"Content-Type": {"application/json"},
	}
	if e.RetryAfter != "" {
		headers["Retry-After"] = []string{e.RetryAfter}
	}
	return headers
}

// IsHTTPError reports whether statusCode is outside the 2xx success range.
func IsHTTPError(statusCode int) bool {
	return statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices
}

// IsBackendError reports whether err (or any error in its chain) is a
// BackendError.
func IsBackendError(err error) (*BackendError, bool) {
	var be *BackendError
	if errors.As(err, &be) {
		return be, true
	}
	return nil, false
}
