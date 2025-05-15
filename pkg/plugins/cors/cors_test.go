package cors_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/cors"
	"github.com/NeuralTrust/TrustGate/pkg/types"
)

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		settings    map[string]any
		expectError bool
	}{
		{
			name: "it should succeed with wildcard origin and valid methods",
			settings: map[string]any{
				"allowed_origins": []string{"*"},
				"allowed_methods": []string{"GET", "POST"},
				"max_age":         "1h",
			},
			expectError: false,
		},
		{
			name: "it should fail when allow_credentials is true and allowed_origins is *",
			settings: map[string]any{
				"allowed_origins":   []string{"*"},
				"allowed_methods":   []string{"GET", "POST"},
				"allow_credentials": true,
			},
			expectError: true,
		},
		{
			name: "it should succeed with valid specific origin and method",
			settings: map[string]any{
				"allowed_origins": []string{"https://example.com"},
				"allowed_methods": []string{"GET"},
				"max_age":         "30m",
			},
			expectError: false,
		},
		{
			name: "it should fail for invalid origin scheme",
			settings: map[string]any{
				"allowed_origins": []string{"ftp://example.com"},
				"allowed_methods": []string{"POST"},
			},
			expectError: true,
		},
		{
			name: "it should fail for malformed origin format",
			settings: map[string]any{
				"allowed_origins": []string{"::invalid-url"},
				"allowed_methods": []string{"POST"},
			},
			expectError: true,
		},
		{
			name: "it should fail when allowed_origins is empty",
			settings: map[string]any{
				"allowed_methods": []string{"GET"},
			},
			expectError: true,
		},
		{
			name: "it should fail when allowed_methods is empty",
			settings: map[string]any{
				"allowed_origins": []string{"https://example.com"},
			},
			expectError: true,
		},
		{
			name: "it should fail when allowed_methods contains an invalid HTTP method",
			settings: map[string]any{
				"allowed_origins": []string{"https://example.com"},
				"allowed_methods": []string{"FETCH"},
			},
			expectError: true,
		},
		{
			name: "it should fail when max_age has an invalid duration format",
			settings: map[string]any{
				"allowed_origins": []string{"https://example.com"},
				"allowed_methods": []string{"GET"},
				"max_age":         "not-a-duration",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &cors.CorsPlugin{}
			err := p.ValidateConfig(types.PluginConfig{Settings: tt.settings})
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("did not expect error but got: %v", err)
			}
		})
	}
}

func TestCorsPlugin_Execute(t *testing.T) {
	plugin := &cors.CorsPlugin{}

	tests := []struct {
		name        string
		config      map[string]any
		headers     map[string][]string
		method      string
		expectError bool
		expectCode  int
	}{
		{
			name: "it should reject if allow_credentials is true and origin is *",
			config: map[string]any{
				"allowed_origins":   []string{"*"},
				"allowed_methods":   []string{"GET"},
				"allow_credentials": true,
			},
			headers: map[string][]string{
				"Origin": {"https://example.com"},
			},
			method:      http.MethodGet,
			expectError: true,
			expectCode:  http.StatusForbidden,
		},
		{
			name: "it should reject unknown origin",
			config: map[string]any{
				"allowed_origins": []string{"https://trustgate.ai"},
				"allowed_methods": []string{"GET"},
			},
			headers: map[string][]string{
				"Origin": {"https://evil.com"},
			},
			method:      http.MethodGet,
			expectError: true,
			expectCode:  http.StatusForbidden,
		},
		{
			name: "it should apply headers for valid origin",
			config: map[string]any{
				"allowed_origins": []string{"https://example.com"},
				"allowed_methods": []string{"GET"},
			},
			headers: map[string][]string{
				"Origin": {"https://example.com"},
			},
			method:      http.MethodGet,
			expectError: false,
			expectCode:  http.StatusOK,
		},
		{
			name: "it should reject preflight with missing requested method",
			config: map[string]any{
				"allowed_origins": []string{"https://example.com"},
				"allowed_methods": []string{"GET"},
			},
			headers: map[string][]string{
				"Origin": {"https://example.com"},
			},
			method:      http.MethodOptions,
			expectError: true,
			expectCode:  http.StatusBadRequest,
		},
		{
			name: "it should reject preflight with disallowed method",
			config: map[string]any{
				"allowed_origins": []string{"https://example.com"},
				"allowed_methods": []string{"GET"},
			},
			headers: map[string][]string{
				"Origin":                        {"https://example.com"},
				"Access-Control-Request-Method": {"DELETE"},
			},
			method:      http.MethodOptions,
			expectError: true,
			expectCode:  http.StatusMethodNotAllowed,
		},
		{
			name: "it should allow valid preflight request",
			config: map[string]any{
				"allowed_origins": []string{"https://example.com"},
				"allowed_methods": []string{"GET", "POST"},
			},
			headers: map[string][]string{
				"Origin":                        {"https://example.com"},
				"Access-Control-Request-Method": {"POST"},
			},
			method:      http.MethodOptions,
			expectError: true,
			expectCode:  http.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &types.RequestContext{
				Context: context.Background(),
				Method:  tt.method,
				Headers: tt.headers,
			}
			resp := &types.ResponseContext{
				Headers: map[string][]string{},
			}
			config := types.PluginConfig{
				Settings: tt.config,
			}

			result, err := plugin.Execute(context.Background(), config, req, resp, metrics.NewEventContext("", "", nil))

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error, got none")
				} else {
					var perr *types.PluginError
					if errors.As(err, &perr) {
						if perr.StatusCode != tt.expectCode {
							t.Errorf("expected code %d, got %d", tt.expectCode, perr.StatusCode)
						}
					} else {
						t.Errorf("expected PluginError, got different error type: %v", err)
					}
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result == nil {
					t.Errorf("expected PluginResponse, got nil")
				} else if result.StatusCode != tt.expectCode {
					t.Errorf("expected status %d, got %d", tt.expectCode, result.StatusCode)
				}
			}
		})
	}

}
