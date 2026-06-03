package proxy

import (
	"errors"
	"net/http"
	"testing"
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
