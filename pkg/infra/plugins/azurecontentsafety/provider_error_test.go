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

package azurecontentsafety

import (
	"context"
	"net/http"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// The error answers of text:analyze in the shape Azure AI services document:
// {"error":{"code":...,"message":...}}. A 400 is Azure refusing the text it was
// sent, which is the request's own content; credentials, throttling, timeouts
// and 5xx are Azure's availability.
var azureAnalyzeErrors = []struct {
	name    string
	status  int
	body    string
	isInput bool
}{
	{"invalid request body", http.StatusBadRequest, `{"error":{"code":"InvalidRequestBody","message":"The request body is invalid."}}`, true},
	{"invalid parameter", http.StatusBadRequest, `{"error":{"code":"InvalidParameter","message":"The parameter text is invalid.","target":"text"}}`, true},
	{"payload too large", http.StatusRequestEntityTooLarge, `{"error":{"code":"RequestEntityTooLarge","message":"Request body is too large."}}`, true},
	{"bad key", http.StatusUnauthorized, `{"error":{"code":"401","message":"Access denied due to invalid subscription key or wrong API endpoint."}}`, false},
	{"forbidden", http.StatusForbidden, `{"error":{"code":"403","message":"Out of call volume quota."}}`, false},
	{"throttled", http.StatusTooManyRequests, `{"error":{"code":"429","message":"Rate limit is exceeded. Try again in 1 seconds."}}`, false},
	{"request timeout", http.StatusRequestTimeout, `{"error":{"code":"408","message":"timeout"}}`, false},
	{"server error", http.StatusInternalServerError, `{"error":{"code":"InternalServerError","message":"internal"}}`, false},
	{"unavailable", http.StatusServiceUnavailable, `{"error":{"code":"ServiceUnavailable","message":"unavailable"}}`, false},
}

func TestExecuteProviderErrorByClass(t *testing.T) {
	t.Parallel()
	for _, tc := range azureAnalyzeErrors {
		for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
			t.Run(tc.name+" "+string(mode), func(t *testing.T) {
				t.Parallel()
				f := &fakeAzure{status: tc.status, rawBody: tc.body}
				srv := newServer(t, f)
				p := New(adapter.NewRegistry(), nil)
				event, span := eventFor(t)
				in := execInput(policy.StagePreRequest, mode, settings(srv.URL, map[string]int{CategoryHate: 2}), requestContext(openAIRequestBody()))
				in.Event = event

				res, err := p.Execute(context.Background(), in)

				wantDecision, wantClass, wantReason, refused := "failed_open", "availability", "transport", false
				if tc.isInput {
					wantClass, wantReason = "input", "input_too_large"
					if mode == policy.ModeEnforce {
						wantDecision, refused = "failed_closed", true
					}
				}
				if refused {
					pe, ok := appplugins.AsPluginError(err)
					if !ok || pe.StatusCode != http.StatusForbidden || pe.Type != appplugins.TypeGuardrailInputUninspectable {
						t.Fatalf("want a 403 guardrail_input_uninspectable, got res=%+v err=%v", res, err)
					}
				} else if err != nil || res == nil || res.StatusCode != http.StatusOK {
					t.Fatalf("want a pass-through, got res=%+v err=%v", res, err)
				}
				extras, ok := span.PluginAttrsCopy().Extras.(*Data)
				if !ok || extras.Decision != wantDecision || extras.FailureClass != wantClass || extras.FailureReason != wantReason {
					t.Fatalf("extras = %+v, ok=%v, want %s/%s/%s", extras, ok, wantDecision, wantClass, wantReason)
				}
			})
		}
	}
}
