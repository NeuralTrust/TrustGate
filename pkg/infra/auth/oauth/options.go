package oauth

import (
	"net/http"
	"time"
)

// TokenClientOption is a function that configures a TokenClient
type TokenClientOption func(*tokenClient)

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(client *http.Client) TokenClientOption {
	return func(tc *tokenClient) {
		if client != nil {
			tc.http = client
		}
	}
}

// WithTimeout sets the HTTP client timeout
func WithTimeout(timeout time.Duration) TokenClientOption {
	return func(tc *tokenClient) {
		if tc.http != nil {
			tc.http.Timeout = timeout
		}
	}
}

