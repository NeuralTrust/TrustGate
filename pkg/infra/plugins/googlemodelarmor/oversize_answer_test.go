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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// oversizeAnswerStub answers a sanitize call with a de-identify result above the
// 1 MiB the client reads. A chunk is at most 57,344 bytes and JSON escaping
// grows it at most six-fold, so only a provider answering with more than it was
// sent can do this, and the client cannot tell that from a text chosen to grow.
func oversizeAnswerStub(t *testing.T) *modelArmorStub {
	t.Helper()
	s := &modelArmorStub{}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		text, _ := json.Marshal(strings.Repeat("x", 2<<20))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sanitizeOpen +
			`"sdp":{"sdpFilterResult":{"deidentifyResult":{"matchState":"MATCH_FOUND","infoTypes":["EMAIL_ADDRESS"],"data":{"text":` + string(text) + `}}}}` +
			sanitizeClose))
	}))
	t.Cleanup(s.server.Close)
	return s
}

// A provider answer above the response limit is read as input, not as an
// outage: letting it through would hand the client a way to have its email
// forwarded unmasked, so a mode that blocks refuses it and observe records it.
func TestAnAnswerAboveTheLimitIsInput(t *testing.T) {
	t.Parallel()
	text := "reach me at victim@example.com"
	raw, err := json.Marshal(map[string]any{"model": "gpt-4o", "messages": []map[string]string{{"role": "user", "content": text}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []policy.Mode{policy.ModeEnforce, policy.ModeObserve} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			stub := oversizeAnswerStub(t)
			p := pluginWithStub(stub)
			event, span := newStreamEvent()
			settings := modelArmorSettings()
			settings["sdp_action"] = sdpActionAnonymize
			in := execInput(policy.StagePreRequest, mode, settings, reqCtx(raw), nil)
			in.Event = event

			res, err := p.Execute(context.Background(), in)

			data, ok := span.PluginAttrsCopy().Extras.(*Data)
			if !ok {
				t.Fatalf("extras = %T", span.PluginAttrsCopy().Extras)
			}
			if data.FailureClass != "input" {
				t.Fatalf("failure_class = %q (reason %q), want input", data.FailureClass, data.FailureReason)
			}
			if mode == policy.ModeEnforce {
				pe, isPE := appplugins.AsPluginError(err)
				if !isPE || pe.Type != appplugins.TypeGuardrailInputUninspectable {
					t.Fatalf("want a 403 guardrail_input_uninspectable, got res=%+v err=%v", res, err)
				}
				return
			}
			assertPassThrough(t, res, err)
			if data.Decision != "failed_open" {
				t.Fatalf("decision = %q", data.Decision)
			}
		})
	}
}
