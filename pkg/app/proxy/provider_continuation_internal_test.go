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
	"encoding/json"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fieldString(t *testing.T, body []byte, field string) (string, bool) {
	t.Helper()
	var obj map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body, &obj))
	raw, ok := obj[field]
	if !ok {
		return "", false
	}
	var s string
	require.NoError(t, json.Unmarshal(raw, &s))
	return s, true
}

func TestInjectPreviousResponseID_ResponsesFormat(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","input":"hi"}`)
	out := injectPreviousResponseID(body, adapter.FormatOpenAIResponses, "resp_abc")

	got, ok := fieldString(t, out, "previous_response_id")
	require.True(t, ok)
	assert.Equal(t, "resp_abc", got)
}

func TestInjectPreviousResponseID_SkipsNonResponsesFormat(t *testing.T) {
	body := []byte(`{"model":"gpt-4o"}`)
	out := injectPreviousResponseID(body, adapter.FormatOpenAI, "resp_abc")
	_, ok := fieldString(t, out, "previous_response_id")
	assert.False(t, ok, "previous_response_id only applies to the Responses format")
}

func TestInjectPreviousResponseID_SkipsForeignTurnID(t *testing.T) {
	body := []byte(`{"model":"gpt-4o"}`)
	out := injectPreviousResponseID(body, adapter.FormatOpenAIResponses, "chatcmpl-xyz")
	_, ok := fieldString(t, out, "previous_response_id")
	assert.False(t, ok)
}

func TestInjectPreviousResponseID_DoesNotOverrideClientValue(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","previous_response_id":"resp_client"}`)
	out := injectPreviousResponseID(body, adapter.FormatOpenAIResponses, "resp_gateway")
	got, ok := fieldString(t, out, "previous_response_id")
	require.True(t, ok)
	assert.Equal(t, "resp_client", got, "an explicit client value wins")
}

func TestInjectPreviousResponseID_EmptyIDAndBadJSON(t *testing.T) {
	body := []byte(`{"model":"gpt-4o"}`)
	assert.Equal(t, body, injectPreviousResponseID(body, adapter.FormatOpenAIResponses, ""))

	bad := []byte(`not-json`)
	assert.Equal(t, bad, injectPreviousResponseID(bad, adapter.FormatOpenAIResponses, "resp_abc"))
}
