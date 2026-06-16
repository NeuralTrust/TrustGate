// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
		Config:   policy.PluginConfig{ID: "rs-1", Slug: PluginName, Name: PluginName, Settings: settings},
		Request:  req,
		Response: &infracontext.ResponseContext{},
	}
}

func TestPlugin_Stages(t *testing.T) {
	p := New()
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, p.MandatoryStages())
	assert.Equal(t, []policy.Stage{policy.StagePreRequest}, p.SupportedStages())
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

func TestPlugin_Execute_ObserveDoesNotBlock(t *testing.T) {
	p := New()
	assert.Equal(t, []policy.Mode{policy.ModeEnforce, policy.ModeObserve}, p.SupportedModes())

	settings := map[string]any{"allowed_payload_size": 10, "size_unit": "bytes"}
	req := &infracontext.RequestContext{Body: []byte("this body is definitely longer than ten bytes")}
	in := input(settings, req)
	in.Mode = policy.ModeObserve

	res, err := p.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 200, res.StatusCode)
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
