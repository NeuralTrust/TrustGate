package cors

import (
	"context"
	"net/http"
	"testing"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func input(settings map[string]any, req *infracontext.RequestContext) appplugins.ExecInput {
	return appplugins.ExecInput{
		Stage:    policy.StagePreRequest,
		Config:   policy.Plugin{ID: "cors-1", Name: PluginName, Settings: settings},
		Request:  req,
		Response: &infracontext.ResponseContext{},
	}
}

func baseSettings() map[string]any {
	return map[string]any{
		"allowed_origins": []any{"https://allowed.com"},
		"allowed_methods": []any{"GET", "POST"},
	}
}

func TestPlugin_Stages(t *testing.T) {
	p := New()
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, p.Stages())
	assert.Equal(t, PluginName, p.Name())
}

func TestPlugin_ValidateConfig(t *testing.T) {
	tests := []struct {
		name     string
		settings map[string]any
		wantErr  bool
	}{
		{name: "valid", settings: baseSettings()},
		{name: "no origins", settings: map[string]any{"allowed_methods": []any{"GET"}}, wantErr: true},
		{name: "bad origin", settings: map[string]any{"allowed_origins": []any{"not-a-url"}, "allowed_methods": []any{"GET"}}, wantErr: true},
		{name: "credentials with wildcard", settings: map[string]any{"allowed_origins": []any{"*"}, "allowed_methods": []any{"GET"}, "allow_credentials": true}, wantErr: true},
		{name: "bad method", settings: map[string]any{"allowed_origins": []any{"*"}, "allowed_methods": []any{"FLY"}}, wantErr: true},
		{name: "bad max age", settings: map[string]any{"allowed_origins": []any{"*"}, "allowed_methods": []any{"GET"}, "max_age": "soon"}, wantErr: true},
	}
	p := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.ValidateConfig(tt.settings)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestPlugin_Execute_MissingOrigin(t *testing.T) {
	p := New()
	req := &infracontext.RequestContext{Method: http.MethodGet, Headers: map[string][]string{}}
	_, err := p.Execute(context.Background(), input(baseSettings(), req))
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
}

func TestPlugin_Execute_OriginNotAllowed(t *testing.T) {
	p := New()
	req := &infracontext.RequestContext{Method: http.MethodGet, Headers: map[string][]string{"Origin": {"https://evil.com"}}}
	_, err := p.Execute(context.Background(), input(baseSettings(), req))
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
}

func TestPlugin_Execute_SimpleRequestSetsHeaders(t *testing.T) {
	p := New()
	req := &infracontext.RequestContext{Method: http.MethodGet, Headers: map[string][]string{"Origin": {"https://allowed.com"}}}
	res, err := p.Execute(context.Background(), input(baseSettings(), req))
	require.NoError(t, err)
	require.False(t, res.StopUpstream)
	assert.Equal(t, []string{"https://allowed.com"}, res.Headers["Access-Control-Allow-Origin"])
	assert.Equal(t, []string{"Origin"}, res.Headers["Vary"])
}

func TestPlugin_Execute_PreflightShortCircuits(t *testing.T) {
	p := New()
	settings := baseSettings()
	settings["max_age"] = "600s"
	req := &infracontext.RequestContext{
		Method: http.MethodOptions,
		Headers: map[string][]string{
			"Origin":                         {"https://allowed.com"},
			"Access-Control-Request-Method":  {"POST"},
			"Access-Control-Request-Headers": {"X-Custom"},
		},
	}
	res, err := p.Execute(context.Background(), input(settings, req))
	require.NoError(t, err)
	require.True(t, res.StopUpstream)
	assert.Equal(t, http.StatusNoContent, res.StatusCode)
	assert.Equal(t, []string{"GET, POST"}, res.Headers["Access-Control-Allow-Methods"])
	assert.Equal(t, []string{"X-Custom"}, res.Headers["Access-Control-Allow-Headers"])
	assert.Equal(t, []string{"600s"}, res.Headers["Access-Control-Max-Age"])
}

func TestPlugin_Execute_PreflightMissingMethod(t *testing.T) {
	p := New()
	req := &infracontext.RequestContext{
		Method:  http.MethodOptions,
		Headers: map[string][]string{"Origin": {"https://allowed.com"}},
	}
	_, err := p.Execute(context.Background(), input(baseSettings(), req))
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, pe.StatusCode)
}

func TestPlugin_Execute_PreflightMethodNotAllowed(t *testing.T) {
	p := New()
	req := &infracontext.RequestContext{
		Method: http.MethodOptions,
		Headers: map[string][]string{
			"Origin":                        {"https://allowed.com"},
			"Access-Control-Request-Method": {"DELETE"},
		},
	}
	_, err := p.Execute(context.Background(), input(baseSettings(), req))
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, http.StatusMethodNotAllowed, pe.StatusCode)
}
