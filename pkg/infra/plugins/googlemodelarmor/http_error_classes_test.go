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

package googlemodelarmor

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// The google.rpc.Status bodies the Google APIs answer with, as the REST
// transport serialises them (https://cloud.google.com/apis/design/errors).
const (
	rpcInvalidResourceName = `{"error":{"code":400,"message":"Invalid resource name: projects/p/locations/us-central1/templates/","status":"INVALID_ARGUMENT",` +
		`"details":[{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":[{"field":"name","description":"Invalid resource name"}]}]}}`
	rpcInvalidPayload = `{"error":{"code":400,"message":"Invalid JSON payload received.","status":"INVALID_ARGUMENT",` +
		`"details":[{"@type":"type.googleapis.com/google.rpc.BadRequest","fieldViolations":[{"field":"user_prompt_data.text","description":"Invalid JSON payload received."}]}]}}`
	rpcInvalidNoDetails  = `{"error":{"code":400,"message":"Request contains an invalid argument.","status":"INVALID_ARGUMENT"}}`
	rpcUnauthenticated   = `{"error":{"code":401,"message":"Request had invalid authentication credentials.","status":"UNAUTHENTICATED"}}`
	rpcPermissionDenied  = `{"error":{"code":403,"message":"Permission 'modelarmor.templates.sanitizeUserPrompt' denied.","status":"PERMISSION_DENIED"}}`
	rpcNotFound          = `{"error":{"code":404,"message":"Resource not found.","status":"NOT_FOUND"}}`
	rpcResourceExhausted = `{"error":{"code":429,"message":"Quota exceeded.","status":"RESOURCE_EXHAUSTED"}}`
	rpcUnavailable       = `{"error":{"code":503,"message":"The service is currently unavailable.","status":"UNAVAILABLE"}}`
)

func TestHTTPErrorsAreClassifiedByTheirGoogleRPCBody(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		status int
		body   string
		reason string
		input  bool
	}{
		{"invalid resource name is the template's configuration", http.StatusBadRequest, rpcInvalidResourceName, "config_invalid", false},
		{"invalid payload is the content's", http.StatusBadRequest, rpcInvalidPayload, "input_too_large", true},
		{"a 400 without details is the content's", http.StatusBadRequest, rpcInvalidNoDetails, "input_too_large", true},
		{"payload too large", http.StatusRequestEntityTooLarge, `{"error":{"code":413,"message":"Request payload size exceeds the limit.","status":"INVALID_ARGUMENT"}}`, "input_too_large", true},
		{"unauthenticated", http.StatusUnauthorized, rpcUnauthenticated, "transport", false},
		{"permission denied", http.StatusForbidden, rpcPermissionDenied, "transport", false},
		{"not found", http.StatusNotFound, rpcNotFound, "transport", false},
		{"quota exhausted", http.StatusTooManyRequests, rpcResourceExhausted, "transport", false},
		{"unavailable", http.StatusServiceUnavailable, rpcUnavailable, "transport", false},
	} {
		for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
			t.Run(tc.name+" "+string(mode), func(t *testing.T) {
				t.Parallel()
				p := pluginWithStub(newModelArmorStub(t, tc.status, tc.body))
				event, span := newStreamEvent()
				in := execInput(policy.StagePreRequest, mode, modelArmorSettings(), reqCtx(openAIRequest()), nil)
				in.Event = event

				res, err := p.Execute(context.Background(), in)

				wantDecision, wantClass := "failed_open", "availability"
				refused := false
				if tc.input {
					wantClass = "input"
					if mode == policy.ModeEnforce {
						wantDecision, refused = "failed_closed", true
					}
				}
				if refused {
					pe, ok := appplugins.AsPluginError(err)
					require.True(t, ok, "want a 403, got res=%+v err=%v", res, err)
					assert.Equal(t, http.StatusForbidden, pe.StatusCode)
				} else {
					assertPassThrough(t, res, err)
				}
				data, ok := span.PluginAttrsCopy().Extras.(*Data)
				require.True(t, ok)
				assert.Equal(t, wantDecision, data.Decision)
				assert.Equal(t, wantClass, data.FailureClass)
				assert.Equal(t, tc.reason, data.FailureReason)
			})
		}
	}
}

func TestStreamHTTPErrorsAreClassifiedByTheirGoogleRPCBody(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		status int
		body   string
		cut    bool
	}{
		{"content rejected", http.StatusBadRequest, rpcInvalidPayload, true},
		{"template misconfigured", http.StatusBadRequest, rpcInvalidResourceName, false},
		{"unavailable", http.StatusServiceUnavailable, rpcUnavailable, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := pluginWithStub(newModelArmorStub(t, tc.status, tc.body))
			event, _ := newStreamEvent()
			verdict, err := p.InspectSegment(context.Background(), streamInput(policy.ModeEnforce, streamSettings(nil), event), segment(1, "a streamed answer"))
			if tc.cut {
				require.NoError(t, err)
				require.NotNil(t, verdict)
				assert.True(t, verdict.Block)
				return
			}
			require.Error(t, err)
			assert.Nil(t, verdict)
		})
	}
}

// A buffered text of one chunk is sent whole: Model Armor answers
// EXECUTION_SKIPPED for a filter it could not run, which is the content's and
// decides.
func TestBufferedTextOfOneChunkIsSentWhole(t *testing.T) {
	t.Parallel()
	over := strings.Repeat("a", chunkBytes)
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"` + over + `"}]}`)
	for _, tc := range []struct {
		name     string
		response string
		mode     policy.Mode
		blocked  bool
		detail   string
		class    string
	}{
		{"screened", allowResponse, policy.ModeEnforce, false, "", ""},
		{"skipped in enforce", tokenLimitSkipResponse, policy.ModeEnforce, true, appplugins.DetailFilterNotExecuted, "input"},
		{"skipped in observe", tokenLimitSkipResponse, policy.ModeObserve, false, appplugins.DetailFilterNotExecuted, "input"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stub := newModelArmorStub(t, http.StatusOK, tc.response)
			p := pluginWithStub(stub)
			event, span := newStreamEvent()
			in := execInput(policy.StagePreRequest, tc.mode, modelArmorSettings(), reqCtx(body), nil)
			in.Event = event

			res, err := p.Execute(context.Background(), in)
			if tc.blocked {
				pe, ok := appplugins.AsPluginError(err)
				require.True(t, ok, "got %v", err)
				assert.Equal(t, http.StatusForbidden, pe.StatusCode)
			} else {
				assertPassThrough(t, res, err)
			}
			assert.Equal(t, 1, stub.count())
			assert.Contains(t, string(stub.lastBody), over)
			data, ok := span.PluginAttrsCopy().Extras.(*Data)
			require.True(t, ok)
			assert.Equal(t, tc.detail, data.FailureDetail)
			assert.Equal(t, tc.class, data.FailureClass)
		})
	}
}
