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

package proxy

import (
	"context"
	"net/http"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pluginErrorResult is the single renderer of a plugin's denial; the direction
// header the executor stamped on the error must reach the response untouched.
func TestPluginErrorResult_KeepsTheBlockDirectionHeader(t *testing.T) {
	t.Parallel()
	pe := appplugins.WithBlockDirection(
		&appplugins.PluginError{StatusCode: http.StatusForbidden, Type: "x_blocked", Message: "no"},
		appplugins.BlockDirectionInput)
	res := pluginErrorResult(pe)
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
	assert.Equal(t, []string{appplugins.BlockDirectionInput}, res.Headers[appplugins.BlockDirectionHeader])
	assert.Equal(t, []string{"application/json"}, res.Headers["Content-Type"])

	rate := pluginErrorResult(appplugins.WithBlockDirection(
		&appplugins.PluginError{StatusCode: http.StatusTooManyRequests, Message: "slow"},
		appplugins.BlockDirectionInput))
	assert.NotContains(t, rate.Headers, appplugins.BlockDirectionHeader)
}

func TestStreamError_UnverifiableCarriesNoDirectionHeader(t *testing.T) {
	t.Parallel()
	unverifiable := streamError(adapter.FormatOpenAI, streamUnverifiableType, streamUnverifiableMessage)
	assert.Equal(t, http.StatusForbidden, unverifiable.StatusCode)
	assert.NotContains(t, unverifiable.Headers, appplugins.BlockDirectionHeader)

	blocked := streamError(adapter.FormatOpenAI, "x_blocked", "no")
	assert.Equal(t, []string{appplugins.BlockDirectionOutput}, blocked.Headers[appplugins.BlockDirectionHeader])
}

func TestNativeShortCircuit_CarriesTheDirectionOfItsStage(t *testing.T) {
	t.Parallel()
	req := &infracontext.RequestContext{BedrockNative: &infracontext.BedrockNativeTarget{Op: "converse", ModelID: "m"}}
	short := &ForwardResult{StatusCode: http.StatusOK}
	for stage, want := range map[policydomain.Stage]string{
		policydomain.StagePreRequest:  appplugins.BlockDirectionInput,
		policydomain.StagePreResponse: appplugins.BlockDirectionOutput,
	} {
		res := nativeShortCircuit(req, short, stage)
		assert.Equal(t, http.StatusForbidden, res.StatusCode)
		assert.Equal(t, []string{want}, res.Headers[appplugins.BlockDirectionHeader], string(stage))
	}
}

type modifyingExecutor struct{}

func (*modifyingExecutor) RunStage(_ context.Context, in appplugins.StageInput) (*appplugins.StageOutcome, error) {
	in.Response.StatusCode = http.StatusAccepted
	return &appplugins.StageOutcome{}, nil
}

// A plugin that changes a native response without declaring a mask is refused
// by the forwarder itself, not by RunStage, so it stamps the header itself.
func TestFinalizeBody_NativeResponseModifiedCarriesOutputDirection(t *testing.T) {
	t.Parallel()
	req := &infracontext.RequestContext{
		SourceFormat:  string(adapter.FormatBedrockNative),
		BedrockNative: &infracontext.BedrockNativeTarget{Op: "converse", ModelID: "m"},
		NativeMask:    &infracontext.NativeMaskLog{},
	}
	fwd := &forwarder{executor: &modifyingExecutor{}, codec: adapter.NewRegistry(), logger: newGuardLogger()}
	dto := &forwardRequestDTO{request: req, response: &infracontext.ResponseContext{}}
	res, pe := fwd.finalizeBodyGated(context.Background(), dto, &ProviderResponse{StatusCode: http.StatusOK, Body: []byte(`{}`)})
	require.NotNil(t, pe)
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
	assert.Equal(t, []string{appplugins.BlockDirectionOutput}, res.Headers[appplugins.BlockDirectionHeader])
}
