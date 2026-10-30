// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package registry

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var ErrCredentialAcquisition = errors.New("provider credential acquisition failed")

// ErrCallerCredentialRejected reports that a provider credential the caller
// sent on a passthrough registry is unusable. It wraps
// ErrCredentialAcquisition, so the proxy still treats it as terminal.
var ErrCallerCredentialRejected = fmt.Errorf("%w: the provider credential sent by the caller was rejected", ErrCredentialAcquisition)

// BackendError represents a non-2xx response received from a backend target
// (the upstream LLM provider). It carries the status code and raw body; the
// proxy relays the error to the client through adapter.ClientErrorBody.
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
