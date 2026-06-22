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

package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestBackendFailureStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		status int
		want   bool
	}{
		{http.StatusOK, false},
		{http.StatusCreated, false},
		{http.StatusBadRequest, false},
		{http.StatusUnauthorized, false},
		{http.StatusForbidden, false},
		{http.StatusNotFound, false},
		{http.StatusUnprocessableEntity, false},
		{http.StatusRequestTimeout, true},
		{http.StatusTooManyRequests, true},
		{http.StatusInternalServerError, true},
		{http.StatusBadGateway, true},
		{http.StatusServiceUnavailable, true},
		{http.StatusGatewayTimeout, true},
	}
	for _, tc := range cases {
		if got := backendFailureStatus(tc.status); got != tc.want {
			t.Errorf("backendFailureStatus(%d) = %v, want %v", tc.status, got, tc.want)
		}
	}
}

func TestClassifyOutcome(t *testing.T) {
	t.Parallel()
	committedStream := &ProviderResponse{StatusCode: 200, Stream: func(yield func([]byte, error) bool) {}}
	providerErrBody := []byte(`{"error":{"type":"overloaded_error","message":"overloaded"}}`)

	cases := []struct {
		name     string
		resp     *ProviderResponse
		err      error
		triggers fallbackTriggers
		want     Outcome
	}{
		{"transport error", nil, errors.New("boom"), fallbackTriggers{}, OutcomeRetryable},
		{"model not allowed is terminal", nil, ErrModelNotAllowed, fallbackTriggers{}, OutcomeTerminal},
		{
			"credential acquisition is terminal",
			nil,
			fmt.Errorf("provider completions: %w: secret expired", registrydomain.ErrCredentialAcquisition),
			fallbackTriggers{},
			OutcomeTerminal,
		},
		{"invalid payload is terminal", nil, ErrInvalidRequestPayload, fallbackTriggers{}, OutcomeTerminal},
		{"nil response no error", nil, nil, fallbackTriggers{}, OutcomeRetryable},
		{"committed stream", committedStream, nil, fallbackTriggers{}, OutcomeSuccess},
		{"2xx success", &ProviderResponse{StatusCode: 200}, nil, fallbackTriggers{}, OutcomeSuccess},
		{"500 retryable", &ProviderResponse{StatusCode: 500}, nil, fallbackTriggers{}, OutcomeRetryable},
		{"503 retryable", &ProviderResponse{StatusCode: 503}, nil, fallbackTriggers{}, OutcomeRetryable},
		{"429 retryable", &ProviderResponse{StatusCode: 429}, nil, fallbackTriggers{}, OutcomeRetryable},
		{"408 retryable", &ProviderResponse{StatusCode: 408}, nil, fallbackTriggers{}, OutcomeRetryable},
		{"400 terminal", &ProviderResponse{StatusCode: 400}, nil, fallbackTriggers{}, OutcomeTerminal},
		{"401 terminal", &ProviderResponse{StatusCode: 401}, nil, fallbackTriggers{}, OutcomeTerminal},
		{"404 terminal", &ProviderResponse{StatusCode: 404}, nil, fallbackTriggers{}, OutcomeTerminal},
		{
			name:     "2xx provider_error retryable when trigger on",
			resp:     &ProviderResponse{StatusCode: 200, Body: providerErrBody},
			triggers: fallbackTriggers{providerError: true},
			want:     OutcomeRetryable,
		},
		{
			name:     "2xx provider_error ignored when trigger off",
			resp:     &ProviderResponse{StatusCode: 200, Body: providerErrBody},
			triggers: fallbackTriggers{},
			want:     OutcomeSuccess,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyOutcome(tc.resp, tc.err, tc.triggers); got != tc.want {
				t.Errorf("classifyOutcome = %v, want %v", got, tc.want)
			}
		})
	}
}

type fakeTimeoutErr struct{}

func (fakeTimeoutErr) Error() string   { return "i/o timeout" }
func (fakeTimeoutErr) Timeout() bool   { return true }
func (fakeTimeoutErr) Temporary() bool { return true }

func TestClassifyFailure(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		resp *ProviderResponse
		err  error
		want failureKind
	}{
		{"deadline exceeded", nil, context.DeadlineExceeded, failureTimeout},
		{"net timeout", nil, fakeTimeoutErr{}, failureTimeout},
		{"transport error", nil, errors.New("connection refused"), failureHTTP5xx},
		{"nil response", nil, nil, failureHTTP5xx},
		{"500", &ProviderResponse{StatusCode: 500}, nil, failureHTTP5xx},
		{"503", &ProviderResponse{StatusCode: 503}, nil, failureHTTP5xx},
		{"429", &ProviderResponse{StatusCode: 429}, nil, failureHTTP429},
		{"408", &ProviderResponse{StatusCode: 408}, nil, failureTimeout},
		{"2xx provider error", &ProviderResponse{StatusCode: 200}, nil, failureProviderError},
		{"4xx terminal", &ProviderResponse{StatusCode: 400}, nil, failureNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyFailure(tc.resp, tc.err); got != tc.want {
				t.Errorf("classifyFailure = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFallbackTriggersAllowsFallback(t *testing.T) {
	t.Parallel()
	all := fallbackTriggers{http5xx: true, http429: true, timeout: true, providerError: true, pluginRejection: true}
	cases := []struct {
		name     string
		triggers fallbackTriggers
		kind     failureKind
		want     bool
	}{
		{"5xx enabled", fallbackTriggers{http5xx: true}, failureHTTP5xx, true},
		{"5xx disabled", fallbackTriggers{http429: true}, failureHTTP5xx, false},
		{"429 enabled", fallbackTriggers{http429: true}, failureHTTP429, true},
		{"429 disabled", fallbackTriggers{http5xx: true}, failureHTTP429, false},
		{"timeout enabled", fallbackTriggers{timeout: true}, failureTimeout, true},
		{"timeout disabled", fallbackTriggers{http5xx: true}, failureTimeout, false},
		{"provider error enabled", fallbackTriggers{providerError: true}, failureProviderError, true},
		{"plugin rejection enabled", fallbackTriggers{pluginRejection: true}, failurePluginRejection, true},
		{"none never allows", all, failureNone, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.triggers.allowsFallback(tc.kind); got != tc.want {
				t.Errorf("allowsFallback(%v) = %v, want %v", tc.kind, got, tc.want)
			}
		})
	}
}
