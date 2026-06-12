package registry

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type BackendError struct {
	StatusCode int
	Body       []byte
	RetryAfter string
}

func (e *BackendError) Error() string {
	return fmt.Sprintf("backend responded with status %d", e.StatusCode)
}

func NewBackendError(statusCode int, body []byte) *BackendError {
	return &BackendError{StatusCode: statusCode, Body: body}
}

func NewBackendHTTPError(statusCode int, body []byte, headers http.Header) *BackendError {
	be := NewBackendError(statusCode, body)
	if headers != nil {
		be.RetryAfter = strings.TrimSpace(headers.Get("Retry-After"))
	}
	return be
}

func (e *BackendError) PassthroughHeaders() map[string][]string {
	headers := map[string][]string{
		"Content-Type": {"application/json"},
	}
	if e.RetryAfter != "" {
		headers["Retry-After"] = []string{e.RetryAfter}
	}
	return headers
}

func IsHTTPError(statusCode int) bool {
	return statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices
}

func IsBackendError(err error) (*BackendError, bool) {
	var be *BackendError
	if errors.As(err, &be) {
		return be, true
	}
	return nil, false
}
