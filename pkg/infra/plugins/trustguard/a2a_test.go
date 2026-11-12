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
	assert.Equal(t, "book a flight\n{\"iban\":\"ES9121000418450200051332\"}", payload.Messages[0]["content"])
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
	assert.Equal(t, "done", payload.Messages[0]["content"])
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

func TestA2AMaskVerdictBlocks(t *testing.T) {
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
	assert.NotContains(t, newV2TestPlugin(t, "http://unused").SupportedProtocols(), appplugins.ProtocolA2A)
}
