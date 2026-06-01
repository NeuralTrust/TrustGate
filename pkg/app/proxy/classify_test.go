package proxy

import (
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
