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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func a2aRequest(parts string) *infracontext.RequestContext {
	return &infracontext.RequestContext{
		GatewayID:    "gw-test",
		ConsumerID:   "consumer-9",
		ConsumerType: "A2A",
		A2A:          true,
		A2AMethod:    "message/send",
		Body:         []byte(`{"method":"message/send","agent":"Travel planner","parts":` + parts + `}`),
	}
}

type a2aGuardPayload struct {
	Messages    []map[string]any  `json:"messages"`
	Attachments []GuardAttachment `json:"attachments"`
}

func capturedA2APayload(t *testing.T, f *fakeGuard) a2aGuardPayload {
	t.Helper()
	var out a2aGuardPayload
	require.NoError(t, json.Unmarshal(f.captured().Payload, &out))
	return out
}

func TestA2APayloadCarriesTextDataAndFiles(t *testing.T) {
	t.Parallel()
	f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	raw := base64.StdEncoding.EncodeToString([]byte("%PDF-1.7"))
	req := a2aRequest(`[
		{"type":"text","text":"book a flight"},
		{"type":"data","data":{"iban":"ES9121000418450200051332"}},
		{"type":"file","url":"https://files.example.com/a.pdf","media_type":"application/pdf","filename":"a.pdf"},
		{"type":"file","raw":"` + raw + `","media_type":"application/pdf"}
	]`)

	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil))
	require.NoError(t, err)

	assert.Equal(t, protocolA2A, f.captured().Protocol)
	payload := capturedA2APayload(t, f)
	require.Len(t, payload.Messages, 1)
	assert.Equal(t, "user", payload.Messages[0]["role"])
	assert.Equal(t, []any{
		map[string]any{"type": "text", "text": "book a flight"},
		map[string]any{"type": "text", "text": `{"iban":"ES9121000418450200051332"}`},
	}, payload.Messages[0]["content"], "a block per part, so each is masked on its own")
	assert.Equal(t, []GuardAttachment{
		{Filename: "a.pdf", ContentType: "application/pdf", URL: "https://files.example.com/a.pdf"},
		{Filename: "file", ContentType: "application/pdf", Data: raw},
	}, payload.Attachments)
}

func TestA2APayloadOmitsRawFilesOverTheCap(t *testing.T) {
	t.Parallel()
	f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	req := a2aRequest(`[{"type":"text","text":"summarise"},{"type":"file","raw":"` + strings.Repeat("A", maxBufferedTextBytes) + `"}]`)
	event, span := newEvent()

	_, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil, event))
	require.NoError(t, err)

	assert.Empty(t, capturedA2APayload(t, f).Attachments)
	extras, ok := span.PluginAttrsCopy().Extras.(guardData)
	require.True(t, ok)
	assert.Equal(t, 1, extras.AttachmentsNotInspected)
}

func TestA2AResponsePartsAreSentAsTheAgent(t *testing.T) {
	t.Parallel()
	f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	resp := &infracontext.ResponseContext{Body: []byte(`{"parts":[{"type":"text","text":"done"}]}`)}

	_, err := p.Execute(context.Background(), execInput(policy.StagePreResponse, policy.ModeEnforce, settings(""), a2aRequest(`[]`), resp))
	require.NoError(t, err)

	payload := capturedA2APayload(t, f)
	require.Len(t, payload.Messages, 1)
	assert.Equal(t, "assistant", payload.Messages[0]["role"])
	assert.Equal(t, []any{map[string]any{"type": "text", "text": "done"}}, payload.Messages[0]["content"])
}

func TestA2AWithNothingInspectableIsSkipped(t *testing.T) {
	t.Parallel()
	f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	event, span := newEvent()

	_, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, settings(""), a2aRequest(`[]`), nil, event))
	require.NoError(t, err)

	assert.Zero(t, f.count())
	extras, ok := span.PluginAttrsCopy().Extras.(guardData)
	require.True(t, ok)
	assert.Equal(t, skipReasonNoInspectableInput, extras.SkipReason)
}

// A mask verdict with no blocks to write (a payload of another shape) blocks
// in a mode that blocks, and is only reported in observe mode.
func TestA2AMaskWithNothingToWriteBlocks(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mode    policy.Mode
		blocked bool
	}{
		{mode: policy.ModeEnforce, blocked: true},
		{mode: policy.ModeObserve, blocked: false},
	} {
		t.Run(string(tc.mode), func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{response: GuardResponse{
				Status:             statusTransform,
				TransformedPayload: map[string]any{"input": "card ****"},
			}}
			p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
			req := a2aRequest(`[{"type":"text","text":"card 4111111111111111"}]`)

			res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, tc.mode, settings(""), req, nil))

			if !tc.blocked {
				require.NoError(t, err)
				assert.Nil(t, res.RequestBody)
				return
			}
			pe, ok := appplugins.AsPluginError(err)
			require.True(t, ok)
			assert.Equal(t, appplugins.TypeMaskUnsupported, pe.Type)
			assert.Equal(t, http.StatusForbidden, pe.StatusCode)
		})
	}
}

func TestSupportedProtocolsDeclareA2AOnlyOnV1(t *testing.T) {
	t.Parallel()
	assert.Contains(t, newTestPlugin(t, adapter.NewRegistry(), "http://unused").SupportedProtocols(), appplugins.ProtocolA2A)
	assert.Contains(t, newV2TestPlugin(t, "http://unused").SupportedProtocols(), appplugins.ProtocolA2A)
}

// maskedBlocks is a TrustGuard transform verdict whose payload is the A2A
// evaluate's one message with these block texts, as DLP masks it.
func maskedBlocks(texts ...string) GuardResponse {
	content := make([]any, len(texts))
	for i, text := range texts {
		content[i] = map[string]any{"type": "text", "text": text}
	}
	return GuardResponse{
		Status:             statusTransform,
		TransformedPayload: map[string]any{"messages": []any{map[string]any{"role": "user", "content": content}}},
	}
}

func decodedA2A(t *testing.T, raw []byte) appplugins.A2ABody {
	t.Helper()
	var body appplugins.A2ABody
	require.NoError(t, json.Unmarshal(raw, &body))
	return body
}

// A mask on A2A is written into the parts it was found in, the text of a text
// part and the JSON of a data part, and handed back for the gateway to write
// into the call.
func TestA2AMaskIsWrittenIntoTheParts(t *testing.T) {
	t.Parallel()
	f := &fakeGuard{response: maskedBlocks("card [MASKED_PAYMENT_CARD]", `{"iban":"[MASKED_BANK_ACCOUNT]"}`)}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	req := a2aRequest(`[{"type":"text","text":"card 4111111111111111"},{"type":"data","data":{"iban":"ES9121000418450200051332"}},{"type":"file","url":"https://files.example.com/a.pdf"}]`)

	res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil))

	require.NoError(t, err)
	require.NotNil(t, res.RequestBody)
	got := decodedA2A(t, res.RequestBody)
	require.Len(t, got.Parts, 3)
	assert.Equal(t, "card [MASKED_PAYMENT_CARD]", got.Parts[0].Text)
	assert.JSONEq(t, `{"iban":"[MASKED_BANK_ACCOUNT]"}`, string(got.Parts[1].Data))
	assert.Equal(t, "https://files.example.com/a.pdf", got.Parts[2].URL, "a file part is left as it is")
	assert.Equal(t, "message/send", got.Method)
}

// On the answer, the masked parts end the response with the new body.
func TestA2AResponseMaskIsHandedBackAsTheAnswer(t *testing.T) {
	t.Parallel()
	f := &fakeGuard{response: maskedBlocks("mail [MASKED_EMAIL]")}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	resp := &infracontext.ResponseContext{Body: []byte(`{"parts":[{"type":"text","text":"mail ana@acme.com"}]}`)}

	res, err := p.Execute(context.Background(), execInput(policy.StagePreResponse, policy.ModeEnforce, settings(""), a2aRequest(`[]`), resp))

	require.NoError(t, err)
	assert.True(t, res.StopUpstream)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "mail [MASKED_EMAIL]", decodedA2A(t, res.Body).Parts[0].Text)
}

// A chunk is read after its prior (what the caller already got), so a value
// split across chunks is seen whole. A mask in the chunk's own text is written
// to it; a mask that reaches into the prior cannot be undone, so it blocks.
func TestA2AChunkIsReadAfterItsPrior(t *testing.T) {
	t.Parallel()
	part := `[{"type":"text","prior":"Contact ana@ac","text":"me.com today"}]`
	for name, tc := range map[string]struct {
		masked  string
		text    string
		refused bool
	}{
		"mask in the chunk":        {masked: "Contact ana@acme.com [MASKED]", text: "me.com [MASKED]"},
		"mask across the boundary": {masked: "Contact [MASKED_EMAIL] today", refused: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{response: maskedBlocks(tc.masked)}
			p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
			resp := &infracontext.ResponseContext{Body: []byte(`{"parts":` + part + `}`)}

			res, err := p.Execute(context.Background(), execInput(policy.StagePreResponse, policy.ModeEnforce, settings(""), a2aRequest(`[]`), resp))

			assert.Equal(t, []any{map[string]any{"type": "text", "text": "Contact ana@acme.com today"}},
				capturedA2APayload(t, f).Messages[0]["content"], "the chunk is sent after its prior")
			if tc.refused {
				pe, ok := appplugins.AsPluginError(err)
				require.True(t, ok)
				assert.Equal(t, appplugins.TypeMaskUnsupported, pe.Type)
				return
			}
			require.NoError(t, err)
			got := decodedA2A(t, res.Body)
			assert.Equal(t, tc.text, got.Parts[0].Text)
			assert.Equal(t, "Contact ana@ac", got.Parts[0].Prior, "the prior is handed back as it was")
		})
	}
}

// A mask that leaves a data part's JSON broken, or does not line up with the
// blocks sent, cannot be written: it blocks.
func TestA2AMaskThatCannotBeWrittenBlocks(t *testing.T) {
	t.Parallel()
	for name, verdict := range map[string]GuardResponse{
		"data no longer JSON": maskedBlocks(`{"card":[MASKED_PAYMENT_CARD]}`),
		"another block count": maskedBlocks("a", "b"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := &fakeGuard{response: verdict}
			p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
			req := a2aRequest(`[{"type":"data","data":{"card":4111111111111111}}]`)

			_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil))

			pe, ok := appplugins.AsPluginError(err)
			require.True(t, ok)
			assert.Equal(t, appplugins.TypeMaskUnsupported, pe.Type)
		})
	}
}
