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

package openaimoderation

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil/textchunk"
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

// A text that splits into more requests than the plugin evaluates is the
// client's doing and cannot be screened whole. It is refused locally as input
// before a call; one that fits a single request is sent whole.
func TestBufferedLegsRefuseATextAboveTheChunkLimitLocally(t *testing.T) {
	t.Parallel()

	for _, stage := range []policy.Stage{policy.StagePreRequest, policy.StagePreResponse} {
		for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
			t.Run(string(stage)+" "+string(mode)+" over", func(t *testing.T) {
				t.Parallel()
				f := &fakeModerator{response: moderationResponse{ID: "m", Results: []moderationResult{{}}}}
				srv := newModeratorServer(t, f)
				p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
				event, span := newEvent()
				big := strings.Repeat("a", 2<<20)
				in := execInput(stage, mode, blockSettings(), requestContext(), nil, event)
				if stage == policy.StagePreRequest {
					in.Request = chatRequestOf(t, big)
				} else {
					in.Request = requestContext()
					in.Response = chatResponseOf(t, big)
				}

				res, err := p.Execute(context.Background(), in)

				f.mu.Lock()
				hits := f.hits
				f.mu.Unlock()
				assert.Zero(t, hits, "an oversize text must not reach OpenAI")
				extras, ok := span.PluginAttrsCopy().Extras.(ModerationData)
				require.True(t, ok)
				assert.Equal(t, "input", extras.FailureClass)
				assert.Equal(t, appplugins.DetailChunkLimit, extras.FailureDetail)
				if mode == policy.ModeEnforce {
					pe, isPE := appplugins.AsPluginError(err)
					require.True(t, isPE, "want a refusal, got res=%v err=%v", res, err)
					assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, "failed_open", extras.Decision)
			})
			t.Run(string(stage)+" "+string(mode)+" under", func(t *testing.T) {
				t.Parallel()
				f := &fakeModerator{response: moderationResponse{ID: "m", Results: []moderationResult{{
					Categories: map[string]bool{"hate": false}, CategoryScores: map[string]float64{"hate": 0.01},
				}}}}
				srv := newModeratorServer(t, f)
				p := New(adapter.NewRegistry(), srv.URL, pluginTestTimeout, nil)
				text := strings.Repeat("a", chunkBytes)
				in := execInput(stage, mode, blockSettings(), requestContext(), nil, nil)
				if stage == policy.StagePreRequest {
					in.Request = chatRequestOf(t, text)
				} else {
					in.Response = chatResponseOf(t, text)
				}
				_, err := p.Execute(context.Background(), in)
				require.NoError(t, err)
				f.mu.Lock()
				defer f.mu.Unlock()
				assert.Equal(t, 1, f.hits)
			})
		}
	}
}

// The ceiling is what half of the budget admits: with the default 15 s budget,
// 4 parallel calls and a 2 s reserve, three rounds, so 12 chunks. A text of 12
// chunks is moderated, and one byte more is refused before any call.
func TestTheChunkCeilingKeepsHalfTheBudgetInHand(t *testing.T) {
	t.Parallel()
	ceiling := textchunk.MaxChunks(maxChunks, evalParallel, callReserve, 15*time.Second)
	require.Equal(t, 12, ceiling)
	atCeiling := chunkBytes + (ceiling-1)*(chunkBytes-chunkOverlap)
	require.Equal(t, ceiling, textchunk.Count(strings.Repeat("a", atCeiling), chunkSpec))

	for _, tc := range []struct {
		name   string
		size   int
		failed bool
	}{{"at the ceiling", atCeiling, false}, {"one byte above", atCeiling + 1, true}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := &fakeModerator{response: moderationResponse{ID: "m", Results: []moderationResult{{
				Categories: map[string]bool{"hate": false}, CategoryScores: map[string]float64{"hate": 0.01},
			}}}}
			srv := newModeratorServer(t, f)
			p := New(adapter.NewRegistry(), srv.URL, 15*time.Second, nil)
			event, span := newEvent()
			in := execInput(policy.StagePreRequest, policy.ModeEnforce, blockSettings(), chatRequestOf(t, strings.Repeat("a", tc.size)), nil, event)

			_, err := p.Execute(context.Background(), in)

			f.mu.Lock()
			defer f.mu.Unlock()
			if !tc.failed {
				require.NoError(t, err)
				assert.Equal(t, ceiling, f.hits)
				return
			}
			require.Error(t, err)
			assert.Zero(t, f.hits)
			extras, ok := span.PluginAttrsCopy().Extras.(ModerationData)
			require.True(t, ok)
			assert.Equal(t, appplugins.DetailChunkLimit, extras.FailureDetail)
		})
	}
}
