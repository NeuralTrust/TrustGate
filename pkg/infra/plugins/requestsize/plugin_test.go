package requestsize

import (
	"context"
	"strings"
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
		Config:   policy.Plugin{ID: "rs-1", Name: PluginName, Settings: settings},
		Request:  req,
		Response: &infracontext.ResponseContext{},
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
		{name: "valid", settings: map[string]any{"allowed_payload_size": 10, "size_unit": "megabytes"}},
		{name: "zero payload", settings: map[string]any{"allowed_payload_size": 0}, wantErr: true},
		{name: "bad unit", settings: map[string]any{"allowed_payload_size": 5, "size_unit": "gigabytes"}, wantErr: true},
		{name: "negative chars", settings: map[string]any{"allowed_payload_size": 5, "max_chars_per_request": -1}, wantErr: true},
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

func TestPlugin_Execute_AllowsSmallBody(t *testing.T) {
	p := New()
	settings := map[string]any{"allowed_payload_size": 1, "size_unit": "kilobytes"}
	req := &infracontext.RequestContext{Body: []byte("hello")}

	res, err := p.Execute(context.Background(), input(settings, req))
	require.NoError(t, err)
	assert.Equal(t, []string{"5"}, res.Headers["X-Request-Size-Bytes"])
	assert.Equal(t, []string{"5"}, res.Headers["X-Request-Size-Chars"])
}

func TestPlugin_Execute_RejectsLargeBytes(t *testing.T) {
	p := New()
	settings := map[string]any{"allowed_payload_size": 10, "size_unit": "bytes"}
	req := &infracontext.RequestContext{Body: []byte("this body is definitely longer than ten bytes")}

	_, err := p.Execute(context.Background(), input(settings, req))
	require.Error(t, err)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 413, pe.StatusCode)
}

func TestPlugin_Execute_RejectsTooManyChars(t *testing.T) {
	p := New()
	settings := map[string]any{"allowed_payload_size": 1, "size_unit": "megabytes", "max_chars_per_request": 5}
	req := &infracontext.RequestContext{Body: []byte(strings.Repeat("x", 6))}

	_, err := p.Execute(context.Background(), input(settings, req))
	require.Error(t, err)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 413, pe.StatusCode)
}

func TestPlugin_Execute_RequiresContentLength(t *testing.T) {
	p := New()
	settings := map[string]any{"allowed_payload_size": 1, "size_unit": "megabytes", "require_content_length": true}
	req := &infracontext.RequestContext{Body: []byte("hi"), Headers: map[string][]string{}}

	_, err := p.Execute(context.Background(), input(settings, req))
	require.Error(t, err)
	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, 411, pe.StatusCode)

	req.Headers["Content-Length"] = []string{"2"}
	_, err = p.Execute(context.Background(), input(settings, req))
	require.NoError(t, err)
}
