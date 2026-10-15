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

package trustguard

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

func chatRequestOf(t *testing.T, text string) *infracontext.RequestContext {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"model": "gpt-4o", "messages": []map[string]string{{"role": "user", "content": text}}})
	require.NoError(t, err)
	req := requestContext()
	req.Body = raw
	return req
}

func chatResponseOf(t *testing.T, text string) *infracontext.ResponseContext {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"id": "c", "object": "chat.completion", "model": "gpt-4o",
		"choices": []map[string]any{{"index": 0, "message": map[string]string{"role": "assistant", "content": text}, "finish_reason": "stop"}},
	})
	require.NoError(t, err)
	return &infracontext.ResponseContext{StatusCode: http.StatusOK, Body: raw}
}

// A request or response whose text is above the ceiling is the client's doing
// and would only be inspected until the call times out, which fails open. It is
// refused locally as input before a call is made; one under it is sent whole.
func TestBufferedLegsRefuseATextAboveTheCeilingLocally(t *testing.T) {
	t.Parallel()

	for _, stage := range []policy.Stage{policy.StagePreRequest, policy.StagePreResponse} {
		for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
			t.Run(string(stage)+" "+string(mode)+" over", func(t *testing.T) {
				t.Parallel()
				f := &fakeGuard{}
				p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
				event, span := newEvent()
				big := strings.Repeat("a", maxBufferedTextBytes+1)
				in := execInputWithEvent(stage, mode, settings(""), requestContext(), nil, event)
				if stage == policy.StagePreRequest {
					in.Request = chatRequestOf(t, big)
				} else {
					in.Response = chatResponseOf(t, big)
				}

				res, err := p.Execute(context.Background(), in)

				assert.Zero(t, f.count(), "an oversize text must not reach TrustGuard")
				extras, ok := span.PluginAttrsCopy().Extras.(guardData)
				require.True(t, ok)
				assert.Equal(t, "input", extras.FailureClass)
				if mode == policy.ModeEnforce {
					pe, isPE := appplugins.AsPluginError(err)
					require.True(t, isPE, "want a refusal, got res=%v err=%v", res, err)
					assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
					assert.Equal(t, decisionFailedClosed, extras.Decision)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, decisionFailedOpen, extras.Decision)
			})
			t.Run(string(stage)+" "+string(mode)+" under", func(t *testing.T) {
				t.Parallel()
				f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
				p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
				text := strings.Repeat("a", 2<<20)
				in := execInput(stage, mode, settings(""), requestContext(), nil)
				if stage == policy.StagePreRequest {
					in.Request = chatRequestOf(t, text)
				} else {
					in.Response = chatResponseOf(t, text)
				}
				_, err := p.Execute(context.Background(), in)
				require.NoError(t, err)
				assert.Equal(t, 1, f.count())
			})
		}
	}
}
