package request_size_limiter

import (
	"context"
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/NeuralTrust/TrustGate/pkg/types"
)

func TestRequestSizeLimiterPlugin_Name(t *testing.T) {
	logger := logrus.New()
	plugin := NewRequestSizeLimiterPlugin(logger)
	assert.Equal(t, PluginName, plugin.Name())
}

func TestRequestSizeLimiterPlugin_AllowedStages(t *testing.T) {
	logger := logrus.New()
	plugin := NewRequestSizeLimiterPlugin(logger)
	stages := plugin.AllowedStages()
	assert.Contains(t, stages, types.PreRequest)
}

func TestRequestSizeLimiterPlugin_ValidateConfig(t *testing.T) {
	logger := logrus.New()
	plugin := NewRequestSizeLimiterPlugin(logger)

	tests := []struct {
		name        string
		config      types.PluginConfig
		expectError bool
	}{
		{
			name: "Valid config with all fields",
			config: types.PluginConfig{
				Settings: map[string]interface{}{
					"allowed_payload_size":   10,
					"size_unit":              "kilobytes",
					"max_chars_per_request":  1000,
					"require_content_length": true,
				},
			},
			expectError: false,
		},
		{
			name: "Valid config with minimal fields",
			config: types.PluginConfig{
				Settings: map[string]interface{}{
					"allowed_payload_size": 10,
				},
			},
			expectError: false,
		},
		{
			name: "Valid config with default size unit",
			config: types.PluginConfig{
				Settings: map[string]interface{}{
					"allowed_payload_size": 10,
					"size_unit":            "",
				},
			},
			expectError: false,
		},
		{
			name: "Invalid payload size",
			config: types.PluginConfig{
				Settings: map[string]interface{}{
					"allowed_payload_size": 0,
				},
			},
			expectError: true,
		},
		{
			name: "Invalid size unit",
			config: types.PluginConfig{
				Settings: map[string]interface{}{
					"allowed_payload_size": 10,
					"size_unit":            "invalid_unit",
				},
			},
			expectError: true,
		},
		{
			name: "Invalid max chars per request",
			config: types.PluginConfig{
				Settings: map[string]interface{}{
					"allowed_payload_size":  10,
					"max_chars_per_request": -1,
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

func TestRequestSizeLimiterPlugin_Execute(t *testing.T) {
	logger := logrus.New()
	plugin := NewRequestSizeLimiterPlugin(logger)
	ctx := context.Background()

	tests := []struct {
		name           string
		config         types.PluginConfig
		requestBody    []byte
		expectError    bool
		expectedStatus int
	}{
		{
			name: "Small request - should pass",
			config: types.PluginConfig{
				Settings: map[string]interface{}{
					"allowed_payload_size":  10,
					"size_unit":             "kilobytes",
					"max_chars_per_request": 1000,
				},
			},
			requestBody:    []byte(`{"message": "This is a small request"}`),
			expectError:    false,
			expectedStatus: 200,
		},
		{
			name: "Request exceeding byte limit - should be blocked",
			config: types.PluginConfig{
				Settings: map[string]interface{}{
					"allowed_payload_size": 10,
					"size_unit":            "bytes",
				},
			},
			requestBody:    []byte(`{"message": "This request is more than 10 bytes"}`),
			expectError:    true,
			expectedStatus: 413,
		},
		{
			name: "Request exceeding character limit - should be blocked",
			config: types.PluginConfig{
				Settings: map[string]interface{}{
					"allowed_payload_size":  1000,
					"max_chars_per_request": 10,
				},
			},
			requestBody:    []byte(`{"message": "This request has more than 10 characters"}`),
			expectError:    true,
			expectedStatus: 413,
		},
		{
			name: "Request with Content-Length header required - should pass",
			config: types.PluginConfig{
				Settings: map[string]interface{}{
					"allowed_payload_size":   10,
					"size_unit":              "kilobytes",
					"require_content_length": true,
				},
			},
			requestBody:    []byte(`{"message": "With Content-Length"}`),
			expectError:    false,
			expectedStatus: 200,
		},
		{
			name: "Default size unit (megabytes) - should pass",
			config: types.PluginConfig{
				Settings: map[string]interface{}{
					"allowed_payload_size": 10,
					// No size_unit specified, should default to megabytes
				},
			},
			requestBody:    []byte(`{"message": "Testing default size unit"}`),
			expectError:    false,
			expectedStatus: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &types.RequestContext{
				Body: tt.requestBody,
				Headers: map[string][]string{
					"Content-Type": {"application/json"},
				},
			}

			// Add Content-Length header if required
			if contentLengthRequired, ok := tt.config.Settings["require_content_length"].(bool); ok && contentLengthRequired {
				req.Headers["Content-Length"] = []string{"30"}
			}

			resp := &types.ResponseContext{
				Headers: make(map[string][]string),
			}

			result, err := plugin.Execute(ctx, tt.config, req, resp, metrics.NewCollector("", nil))

			if tt.expectError {
				assert.Error(t, err)
				// Check if it's a plugin error with the expected status code
				var pluginErr *types.PluginError
				if errors.As(err, &pluginErr) {
					assert.Equal(t, tt.expectedStatus, pluginErr.StatusCode)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tt.expectedStatus, result.StatusCode)

				// Verify headers are set
				assert.Contains(t, result.Headers, "X-Request-Size-Bytes")
				assert.Contains(t, result.Headers, "X-Request-Size-Chars")
				assert.Contains(t, result.Headers, "X-Size-Limit-Bytes")
				assert.Contains(t, result.Headers, "X-Size-Limit-Chars")
			}
		})
	}
}

func TestRequestSizeLimiterPlugin_CountJSONCharacters(t *testing.T) {
	logger := logrus.New()
	plugin, ok := NewRequestSizeLimiterPlugin(logger).(*RequestSizeLimiterPlugin)
	if !ok {
		t.Fatalf("Failed to cast to RequestSizeLimiterPlugin")
	}

	tests := []struct {
		name     string
		input    interface{}
		expected int
	}{
		{
			name:     "String",
			input:    "test",
			expected: 4,
		},
		{
			name:     "Number",
			input:    123,
			expected: 3, // "123"
		},
		{
			name:     "Boolean",
			input:    true,
			expected: 4, // "true"
		},
		{
			name: "Object",
			input: map[string]interface{}{
				"key1": "value1",
				"key2": 123,
			},
			expected: 9, // "value1" + "123"
		},
		{
			name: "Array",
			input: []interface{}{
				"item1",
				"item2",
			},
			expected: 10, // "item1" + "item2"
		},
		{
			name: "Nested",
			input: map[string]interface{}{
				"key1": "value1",
				"key2": []interface{}{
					"item1",
					map[string]interface{}{
						"nested": "value",
					},
				},
			},
			expected: 16, // "value1" + "item1" + "value"
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count := plugin.countJSONCharacters(tt.input)
			assert.Equal(t, tt.expected, count)
		})
	}
}

func TestRemoveWhitespace(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "No whitespace",
			input:    "test",
			expected: "test",
		},
		{
			name:     "With spaces",
			input:    "test with spaces",
			expected: "testwithspaces",
		},
		{
			name:     "With tabs and newlines",
			input:    "test\twith\nnewlines",
			expected: "testwithnewlines",
		},
		{
			name:     "Only whitespace",
			input:    " \t\n\r",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := removeWhitespace(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsWhitespace(t *testing.T) {
	tests := []struct {
		name     string
		input    rune
		expected bool
	}{
		{
			name:     "Space",
			input:    ' ',
			expected: true,
		},
		{
			name:     "Tab",
			input:    '\t',
			expected: true,
		},
		{
			name:     "Newline",
			input:    '\n',
			expected: true,
		},
		{
			name:     "Carriage return",
			input:    '\r',
			expected: true,
		},
		{
			name:     "Letter",
			input:    'a',
			expected: false,
		},
		{
			name:     "Number",
			input:    '1',
			expected: false,
		},
		{
			name:     "Symbol",
			input:    '!',
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isWhitespace(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRemoveSpecialChars(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		pattern  string
		expected string
	}{
		{
			name:     "No special chars",
			input:    "test",
			pattern:  "",
			expected: "test",
		},
		{
			name:     "With punctuation",
			input:    "test.with,punctuation!",
			pattern:  "",
			expected: "testwithpunctuation",
		},
		{
			name:     "With brackets",
			input:    "test(with)[brackets]{here}",
			pattern:  "",
			expected: "testwithbracketshere",
		},
		{
			name:     "With symbols",
			input:    "test@with#symbols$%^&*",
			pattern:  "",
			expected: "testwithsymbols",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := removeSpecialChars(tt.input, tt.pattern)
			assert.Equal(t, tt.expected, result)
		})
	}
}
