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
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/regexreplace"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// RUN-1745: google_model_armor sorts before regex_replace, so at one priority
// it used to run first and send Google the card number regex_replace masks for
// the client. These tests drive the real executor with the real regex_replace
// and a Model Armor plugin pointed at a stub, on the buffered and the streamed
// path, and assert what Google receives.

const rawCard = "card 4111111111111111"

// segmentRunner is the slice of the executor the proxy's stream guard calls.
type segmentRunner interface {
	RunStreamSegment(context.Context, appplugins.StageInput, appplugins.StreamSegment) (*appplugins.SegmentOutcome, error)
}

func maskedRegexSettings() map[string]any {
	return map[string]any{
		"target": "response",
		"rules":  []map[string]any{{"pattern": `\d{16}`, "replacement": "[CARD]"}},
	}
}

func orderedPolicies(regexSet, armorSet map[string]any) []*policy.Policy {
	mk := func(slug string, set map[string]any) *policy.Policy {
		return &policy.Policy{
			ID:       ids.New[ids.PolicyKind](),
			Name:     slug,
			Slug:     slug,
			Enabled:  true,
			Priority: 10,
			Parallel: true,
			Settings: set,
			Stages:   []policy.Stage{policy.StagePreResponse},
			Mode:     policy.ModeEnforce,
		}
	}
	return []*policy.Policy{
		mk(PluginName, armorSet),
		mk(regexreplace.PluginName, regexSet),
	}
}

func orderedExecutor(t *testing.T, stub *modelArmorStub) (appplugins.Registry, appplugins.Executor) {
	t.Helper()
	reg := appplugins.NewRegistry()
	if err := reg.Register(regexreplace.New(adapter.NewRegistry(), nil)); err != nil {
		t.Fatalf("registering regex_replace: %v", err)
	}
	if err := reg.Register(pluginWithStub(stub)); err != nil {
		t.Fatalf("registering google_model_armor: %v", err)
	}
	return reg, appplugins.NewExecutor(reg, nil)
}

func sanitizedText(t *testing.T, stub *modelArmorStub) string {
	t.Helper()
	stub.mu.Lock()
	raw := stub.lastBody
	stub.mu.Unlock()
	var body struct {
		ModelResponseData struct {
			Text string `json:"text"`
		} `json:"modelResponseData"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decoding the sanitize body %q: %v", raw, err)
	}
	return body.ModelResponseData.Text
}

func TestModelArmorAfterRegexReplaceOnTheBufferedResponse(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, allowResponse)
	reg, exec := orderedExecutor(t, stub)
	pols := orderedPolicies(maskedRegexSettings(), modelArmorSettings())

	resp := respCtx([]byte(`{"id":"r1","model":"gpt-4o","choices":[{"message":{"role":"assistant","content":"`+rawCard+`"},"finish_reason":"stop"}]}`), false)
	_, err := exec.RunStage(context.Background(), appplugins.StageInput{
		Stage:    policy.StagePreResponse,
		Plan:     appplugins.NewStagePlan(reg, pols, nil),
		Request:  reqCtx(openAIRequest()),
		Response: resp,
	})
	if err != nil {
		t.Fatalf("RunStage: %v", err)
	}

	if stub.count() != 1 {
		t.Fatalf("sanitize calls = %d, want 1", stub.count())
	}
	if got := sanitizedText(t, stub); got != "card [CARD]" {
		t.Errorf("Model Armor received %q, want the masked text", got)
	}
}

func TestModelArmorAfterRegexReplaceOnAStreamedSegment(t *testing.T) {
	t.Parallel()
	stub := newModelArmorStub(t, http.StatusOK, allowResponse)
	reg, exec := orderedExecutor(t, stub)
	pols := orderedPolicies(maskedRegexSettings(), streamSettings(nil))
	streamer, ok := exec.(segmentRunner)
	if !ok {
		t.Fatal("the executor does not run stream segments")
	}

	out, err := streamer.RunStreamSegment(context.Background(), appplugins.StageInput{
		Stage:    policy.StagePreResponse,
		Plan:     appplugins.NewStagePlan(reg, pols, nil),
		Request:  reqCtx(openAIRequest()),
		Response: &infracontext.ResponseContext{Streaming: true},
	}, appplugins.StreamSegment{StreamID: "s-1", Seq: 1, Text: rawCard, Accumulated: rawCard})
	if err != nil {
		t.Fatalf("RunStreamSegment: %v", err)
	}

	if got := sanitizedText(t, stub); got != "card [CARD]" {
		t.Errorf("Model Armor received %q, want the masked text", got)
	}
	if out == nil || !out.HasTransform || out.Transformed != "card [CARD]" {
		t.Errorf("outcome = %+v, want the regex mask released to the client", out)
	}
}
