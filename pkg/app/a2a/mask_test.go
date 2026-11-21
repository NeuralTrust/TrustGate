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

package a2a_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// masking is an executor whose policy masks at stage: it rewrites the
// normalised body with mask, as TrustGuard's DLP does, at pre_request by
// replacing the request body and at pre_response with a 200 short-circuit.
func masking(stage policy.Stage, mask func(*appplugins.A2ABody)) executorFunc {
	return func(_ context.Context, in appplugins.StageInput) (*appplugins.StageOutcome, error) {
		if in.Stage != stage {
			return &appplugins.StageOutcome{}, nil
		}
		src := in.Request.Body
		if stage == policy.StagePreResponse {
			src = in.Response.Body
		}
		var body appplugins.A2ABody
		if err := json.Unmarshal(src, &body); err != nil {
			return nil, err
		}
		mask(&body)
		out, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		if stage == policy.StagePreRequest {
			in.Request.Body = out
			return &appplugins.StageOutcome{}, nil
		}
		return &appplugins.StageOutcome{ShortCircuit: true, StatusCode: http.StatusOK, Body: out}, nil
	}
}

func decodeJSON(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

func at(t *testing.T, v any, path ...any) any {
	t.Helper()
	for _, seg := range path {
		switch s := seg.(type) {
		case string:
			m, ok := v.(map[string]any)
			require.True(t, ok, "no object at %v", path)
			v = m[s]
		case int:
			l, ok := v.([]any)
			require.True(t, ok, "no list at %v", path)
			v = l[s]
		}
	}
	return v
}

// A mask on the request is written into the call the agent gets: the masked
// text and data, every other member as the caller sent it.
func TestForwarderWritesARequestMaskIntoTheCall(t *testing.T) {
	t.Parallel()
	for v, prefix := range versions {
		ag := newAgent(t, answer(readFixture(t, prefix+".send.response.json")))
		h := newHarness(t, v, ag.URL, masking(policy.StagePreRequest, func(b *appplugins.A2ABody) {
			b.Parts[0].Text = "book a [MASKED]"
			b.Parts[1].Data = json.RawMessage(`{"iban":"[MASKED_BANK_ACCOUNT]"}`)
		}))
		body := readFixture(t, prefix+".send.request.json")

		_, rpcErr := h.send(t, body, nil)
		require.Nil(t, rpcErr, prefix)

		_, got := ag.request(0)
		sent, want := decodeJSON(t, got), decodeJSON(t, body)
		assert.Equal(t, "book a [MASKED]", at(t, sent, "params", "message", "parts", 0, "text"), prefix)
		assert.Equal(t, map[string]any{"iban": "[MASKED_BANK_ACCOUNT]"}, at(t, sent, "params", "message", "parts", 1, "data"), prefix)
		at(t, want, "params", "message", "parts", 0).(map[string]any)["text"] = "book a [MASKED]"
		at(t, want, "params", "message", "parts", 1).(map[string]any)["data"] = map[string]any{"iban": "[MASKED_BANK_ACCOUNT]"}
		assert.Equal(t, want, sent, "%s: nothing else changes", prefix)
	}
}

// A mask on the answer is written into the result the caller gets: the
// status message and the artifact's name here.
func TestForwarderWritesAResponseMaskIntoTheAnswer(t *testing.T) {
	t.Parallel()
	for v, prefix := range versions {
		ag := newAgent(t, answer(readFixture(t, prefix+".send.response.json")))
		h := newHarness(t, v, ag.URL, masking(policy.StagePreResponse, func(b *appplugins.A2ABody) {
			b.Parts[0].Text = "d[MASKED]"
			b.Parts[6].Text = "[MASKED_NAME]"
		}))

		result, rpcErr := h.send(t, readFixture(t, prefix+".send.request.json"), nil)
		require.Nil(t, rpcErr, prefix)

		got := decodeJSON(t, result)
		task := any(got)
		if v == a2a.Version10 {
			task = got["task"]
		}
		assert.Equal(t, "d[MASKED]", at(t, task, "status", "message", "parts", 0, "text"), prefix)
		assert.Equal(t, "[MASKED_NAME]", at(t, task, "artifacts", 0, "name"), prefix)
		assert.Equal(t, "itinerary", at(t, task, "artifacts", 0, "parts", 0, "text"), prefix)
	}
}

// A rewrite the gateway cannot write (a part dropped, a file changed) blocks
// the call instead of sending what the policy flagged. Data that is no longer
// JSON is refused by the plugin itself (trustguard's a2aMasked).
func TestForwarderBlocksAMaskItCannotWrite(t *testing.T) {
	t.Parallel()
	for name, mask := range map[string]func(*appplugins.A2ABody){
		"part dropped": func(b *appplugins.A2ABody) { b.Parts = b.Parts[1:] },
		"file changed": func(b *appplugins.A2ABody) { b.Parts[2].URL = "https://elsewhere.example/a.pdf" },
	} {
		ag := newAgent(t, answer(readFixture(t, "v03.send.response.json")))
		h := newHarness(t, a2a.Version03, ag.URL, masking(policy.StagePreRequest, mask))

		_, rpcErr := h.send(t, readFixture(t, "v03.send.request.json"), nil)

		require.NotNil(t, rpcErr, name)
		assert.Equal(t, a2a.CodePolicyBlocked, rpcErr.Code, name)
		assert.Equal(t, a2a.ReasonMaskUnsupported, reasonOf(t, rpcErr), name)
		assert.Zero(t, ag.calls(), "%s: the agent is never called", name)
	}
}
