package upstream

import (
	"errors"
	"fmt"
	"net/http"
)

type UpstreamError struct {
	StatusCode int
	Body       []byte
}

func (e *UpstreamError) Error() string {
	return fmt.Sprintf("upstream responded with status %d", e.StatusCode)
}

func NewUpstreamError(statusCode int, body []byte) *UpstreamError {
	return &UpstreamError{StatusCode: statusCode, Body: body}
}

func IsHTTPError(statusCode int) bool {
	return statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices
}

func IsUpstreamError(err error) (*UpstreamError, bool) {
	if ue, ok := errors.AsType[*UpstreamError](err); ok {
		return ue, true
	}
	return nil, false
}
