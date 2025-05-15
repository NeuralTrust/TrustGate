package injection_protection

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/NeuralTrust/TrustGate/pkg/types"
)

func TestInjectionProtectionPlugin_Execute(t *testing.T) {
	logger := logrus.New()
	plugin := NewInjectionProtectionPlugin(logger)

	// Create a basic config with SQL injection protection enabled
	config := types.PluginConfig{
		Name:  PluginName,
		Stage: types.PreRequest,
		Settings: map[string]interface{}{
			"predefined_injections": []map[string]interface{}{
				{
					"type":    "sql",
					"enabled": true,
				},
				{
					"type":    "javascript",
					"enabled": true,
				},
			},
			"custom_injections": []map[string]interface{}{
				{
					"name":             "custom_sql",
					"pattern":          "(?i)\\b(select|union|having)\\b",
					"content_to_check": "all",
				},
			},
			"content_to_check": []string{"headers", "path_and_query", "body"},
			"action":           "block",
			"status_code":      400,
			"error_message":    "Potential security threat detected",
		},
	}

	tests := []struct {
		name           string
		req            *types.RequestContext
		resp           *types.ResponseContext
		expectError    bool
		expectedStatus int
	}{
		{
			name: "SQL Injection in Body",
			req: &types.RequestContext{
				Body: []byte(`{"query": "DROP TABLE users"}`),
				Headers: map[string][]string{
					"Content-Type": {"application/json"},
				},
			},
			resp:           &types.ResponseContext{},
			expectError:    true,
			expectedStatus: 400,
		},
		{
			name: "SQL Injection in Header",
			req: &types.RequestContext{
				Headers: map[string][]string{
					"X-Custom-Header": {"DROP TABLE users"},
				},
			},
			resp:           &types.ResponseContext{},
			expectError:    true,
			expectedStatus: 400,
		},
		{
			name: "SQL Injection in Query Parameter",
			req: &types.RequestContext{
				Path: "/api/users",
				Query: url.Values{
					"search": {"DROP TABLE users"},
				},
			},
			resp:           &types.ResponseContext{},
			expectError:    true,
			expectedStatus: 400,
		},
		{
			name: "Custom SQL Pattern in Body",
			req: &types.RequestContext{
				Body: []byte(`{"query": "SELECT * FROM users"}`),
				Headers: map[string][]string{
					"Content-Type": {"application/json"},
				},
			},
			resp:           &types.ResponseContext{},
			expectError:    true,
			expectedStatus: 400,
		},
		{
			name: "Safe Content",
			req: &types.RequestContext{
				Body: []byte(`{"message": "This is a safe message"}`),
				Headers: map[string][]string{
					"Content-Type": {"application/json"},
				},
			},
			resp:           &types.ResponseContext{},
			expectError:    false,
			expectedStatus: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := plugin.Execute(context.Background(), config, tt.req, tt.resp, metrics.NewEventContext("", "", nil))

			if tt.expectError {
				assert.Error(t, err)
				// Check if it's a plugin error with the expected status code
				var pluginErr *types.PluginError
				if errors.As(err, &pluginErr) {
					assert.Equal(t, tt.expectedStatus, pluginErr.StatusCode)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			}
		})
	}
}

func TestInjectionProtectionPlugin_ValidateConfig(t *testing.T) {
	logger := logrus.New()
	plugin := NewInjectionProtectionPlugin(logger)

	tests := []struct {
		name        string
		config      types.PluginConfig
		expectError bool
	}{
		{
			name: "Valid Config",
			config: types.PluginConfig{
				Settings: map[string]interface{}{
					"predefined_injections": []map[string]interface{}{
						{
							"type":    "sql",
							"enabled": true,
						},
					},
					"content_to_check": []string{"body"},
					"action":           "block",
					"status_code":      400,
				},
			},
			expectError: false,
		},
		{
			name: "Missing Content To Check",
			config: types.PluginConfig{
				Settings: map[string]interface{}{
					"predefined_injections": []map[string]interface{}{
						{
							"type":    "sql",
							"enabled": true,
						},
					},
					"action":      "block",
					"status_code": 400,
				},
			},
			expectError: true,
		},
		{
			name: "Invalid Action",
			config: types.PluginConfig{
				Settings: map[string]interface{}{
					"predefined_injections": []map[string]interface{}{
						{
							"type":    "sql",
							"enabled": true,
						},
					},
					"content_to_check": []string{"body"},
					"action":           "invalid_action",
				},
			},
			expectError: true,
		},
		{
			name: "Invalid Status Code",
			config: types.PluginConfig{
				Settings: map[string]interface{}{
					"predefined_injections": []map[string]interface{}{
						{
							"type":    "sql",
							"enabled": true,
						},
					},
					"content_to_check": []string{"body"},
					"action":           "block",
					"status_code":      1000, // Invalid status code
				},
			},
			expectError: true,
		},
		{
			name: "Invalid Custom Injection Pattern",
			config: types.PluginConfig{
				Settings: map[string]interface{}{
					"predefined_injections": []map[string]interface{}{
						{
							"type":    "sql",
							"enabled": true,
						},
					},
					"custom_injections": []map[string]interface{}{
						{
							"name":             "invalid_pattern",
							"pattern":          "[", // Invalid regex pattern
							"content_to_check": "body",
						},
					},
					"content_to_check": []string{"body"},
					"action":           "block",
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := plugin.ValidateConfig(tt.config)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestInjectionProtectionPlugin_Name(t *testing.T) {
	logger := logrus.New()
	plugin := NewInjectionProtectionPlugin(logger)
	assert.Equal(t, PluginName, plugin.Name())
}

func TestInjectionProtectionPlugin_AllowedStages(t *testing.T) {
	logger := logrus.New()
	plugin := NewInjectionProtectionPlugin(logger)
	stages := plugin.AllowedStages()
	assert.Contains(t, stages, types.PreRequest)
}
