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

package plugins

import (
	"context"
	"net/http"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runDenied(t *testing.T, stage policy.Stage, p *fakePlugin) (*StageOutcome, *infracontext.ResponseContext, error) {
	t.Helper()
	p.stages = []policy.Stage{stage}
	exec := NewExecutor(newRegistry(t, p), nil)
	resp := &infracontext.ResponseContext{}
	out, err := exec.RunStage(context.Background(), StageInput{
		Stage:    stage,
		Policies: policies(t, polSpec{slug: p.name, enabled: true}),
		Response: resp,
	})
	return out, resp, err
}

func TestExecutor_RunStage_BlockSetsDirectionHeader(t *testing.T) {
	tests := []struct {
		name  string
		stage policy.Stage
		want  string
	}{
		{"pre_request is input", policy.StagePreRequest, BlockDirectionInput},
		{"pre_response is output", policy.StagePreResponse, BlockDirectionOutput},
		{"post_response is output", policy.StagePostResponse, BlockDirectionOutput},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := runDenied(t, tt.stage, &fakePlugin{
				name: "guard",
				err:  &PluginError{StatusCode: http.StatusForbidden, Type: "x_blocked", Message: "no"},
			})
			pe, ok := AsPluginError(err)
			require.True(t, ok)
			assert.Equal(t, []string{tt.want}, pe.Headers[BlockDirectionHeader])
			assert.Equal(t, "no", pe.Message, "the message is not touched")
		})
	}
}

func TestExecutor_RunStage_NonBlocksDoNotGetDirectionHeader(t *testing.T) {
	for _, status := range []int{
		http.StatusBadRequest,
		http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			_, _, err := runDenied(t, policy.StagePreRequest, &fakePlugin{
				name: "guard",
				err:  &PluginError{StatusCode: status, Message: "x"},
			})
			pe, ok := AsPluginError(err)
			require.True(t, ok)
			assert.NotContains(t, pe.Headers, BlockDirectionHeader)
		})
	}
}

func TestExecutor_RunStage_BlockKeepsPluginHeadersAndSharedError(t *testing.T) {
	shared := &PluginError{
		StatusCode: http.StatusForbidden,
		Message:    "no",
		Headers:    map[string][]string{"Retry-After": {"1"}},
	}
	_, _, err := runDenied(t, policy.StagePreResponse, &fakePlugin{name: "guard", err: shared})
	pe, ok := AsPluginError(err)
	require.True(t, ok)
	assert.Equal(t, []string{"1"}, pe.Headers["Retry-After"])
	assert.Equal(t, []string{BlockDirectionOutput}, pe.Headers[BlockDirectionHeader])
	assert.NotContains(t, shared.Headers, BlockDirectionHeader, "a shared error must not be mutated")
}

func TestExecutor_RunStage_StopUpstream403GetsDirectionHeader(t *testing.T) {
	tests := []struct {
		stage policy.Stage
		want  string
	}{
		{policy.StagePreRequest, BlockDirectionInput},
		{policy.StagePreResponse, BlockDirectionOutput},
	}
	for _, tt := range tests {
		t.Run(string(tt.stage), func(t *testing.T) {
			out, resp, err := runDenied(t, tt.stage, &fakePlugin{
				name:   "allow",
				result: &Result{StopUpstream: true, StatusCode: http.StatusForbidden, Body: []byte(`{}`)},
			})
			require.NoError(t, err)
			require.True(t, out.ShortCircuit)
			assert.Equal(t, []string{tt.want}, out.Headers[BlockDirectionHeader])
			assert.Equal(t, []string{tt.want}, resp.Headers[BlockDirectionHeader])
		})
	}
}

func TestExecutor_RunStage_StopUpstreamMaskGetsNoDirectionHeader(t *testing.T) {
	out, resp, err := runDenied(t, policy.StagePreResponse, &fakePlugin{
		name:   "mask",
		result: &Result{StopUpstream: true, StatusCode: http.StatusOK, Body: []byte(`{}`)},
	})
	require.NoError(t, err)
	require.True(t, out.ShortCircuit)
	assert.NotContains(t, out.Headers, BlockDirectionHeader)
	assert.NotContains(t, resp.Headers, BlockDirectionHeader)
}
