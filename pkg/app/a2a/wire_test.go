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
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/a2a"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The testdata/v03.* and testdata/v10.* files were recorded from a2a-sdk 1.3.0:
// its JSON-RPC server (with 0.3 compatibility on) answering its own clients
// for each version.

var versions = map[a2a.Version]string{a2a.Version03: "v03", a2a.Version10: "v10"}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return raw
}

func decodeFixture(t *testing.T, name string) *a2a.Request {
	t.Helper()
	req, err := a2a.Decode(readFixture(t, name))
	require.NoError(t, err)
	return req
}

func resultOf(t *testing.T, raw []byte) json.RawMessage {
	t.Helper()
	var resp struct {
		Result json.RawMessage `json:"result"`
	}
	require.NoError(t, json.Unmarshal(raw, &resp))
	return resp.Result
}

func rpcCode(t *testing.T, err error) int64 {
	t.Helper()
	var rpcErr *a2a.RPCError
	require.True(t, errors.As(err, &rpcErr), "want an *RPCError, got %v", err)
	return rpcErr.Code
}

func TestMethodKind(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		version a2a.Version
		method  string
		want    a2a.Kind
		ok      bool
	}{
		{a2a.Version03, "message/send", a2a.KindSend, true},
		{a2a.Version03, "message/stream", a2a.KindStream, true},
		{a2a.Version03, "tasks/resubscribe", a2a.KindSubscribe, true},
		{a2a.Version03, "tasks/pushNotificationConfig/set", a2a.KindPush, true},
		{a2a.Version03, "agent/getAuthenticatedExtendedCard", a2a.KindExtendedCard, true},
		{a2a.Version03, "SendMessage", "", false},
		{a2a.Version10, "SendStreamingMessage", a2a.KindStream, true},
		{a2a.Version10, "CancelTask", a2a.KindCancel, true},
		{a2a.Version10, "ListTasks", a2a.KindList, true},
		{a2a.Version10, "ListTaskPushNotificationConfigs", a2a.KindPush, true},
		{a2a.Version10, "GetExtendedAgentCard", a2a.KindExtendedCard, true},
		{a2a.Version10, "message/send", "", false},
		{a2a.Version10, "tools/call", "", false},
	} {
		got, ok := a2a.MethodKind(tc.version, tc.method)
		assert.Equal(t, tc.ok, ok, "%s %s", tc.version, tc.method)
		assert.Equal(t, tc.want, got, "%s %s", tc.version, tc.method)
	}
}

func TestKindRefusal(t *testing.T) {
	t.Parallel()
	for v := range versions {
		assert.Equal(t, a2a.CodeUnsupportedOperation, a2a.KindList.Refusal(v).Code)
		assert.Equal(t, a2a.CodePushNotificationNotSupported, a2a.KindPush.Refusal(v).Code)
		assert.Equal(t, a2a.CodeExtendedCardNotConfigured, a2a.KindExtendedCard.Refusal(v).Code)
		assert.Nil(t, a2a.KindSend.Refusal(v))
	}
	assert.True(t, a2a.KindStream.Streams())
	assert.True(t, a2a.KindSubscribe.Streams())
	assert.False(t, a2a.KindSend.Streams())
}

func TestDecode(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		body   string
		code   int64
		wantID string
	}{
		{name: "not json", body: `{"jsonrpc":`, code: a2a.CodeParseError},
		{name: "batch", body: `[{"jsonrpc":"2.0","id":1,"method":"tasks/get"}]`, code: a2a.CodeInvalidRequest},
		{name: "scalar", body: `"tasks/get"`, code: a2a.CodeInvalidRequest},
		{name: "wrong jsonrpc", body: `{"jsonrpc":"1.0","id":"a","method":"tasks/get"}`, code: a2a.CodeInvalidRequest, wantID: `"a"`},
		{name: "no method", body: `{"jsonrpc":"2.0","id":7}`, code: a2a.CodeInvalidRequest, wantID: `7`},
		{name: "method not a string", body: `{"jsonrpc":"2.0","id":7,"method":1}`, code: a2a.CodeInvalidRequest, wantID: `7`},
		{name: "notification", body: `{"jsonrpc":"2.0","method":"tasks/get"}`, code: a2a.CodeInvalidRequest},
		{name: "object id", body: `{"jsonrpc":"2.0","id":{},"method":"tasks/get"}`, code: a2a.CodeInvalidRequest},
		{name: "method by another case", body: `{"jsonrpc":"2.0","id":1,"METHOD":"tasks/get"}`, code: a2a.CodeInvalidRequest, wantID: `1`},
	} {
		req, err := a2a.Decode([]byte(tc.body))
		assert.Equal(t, tc.code, rpcCode(t, err), tc.name)
		if tc.wantID == "" {
			assert.True(t, req == nil || req.ID == nil, tc.name)
			continue
		}
		require.NotNil(t, req, tc.name)
		assert.Equal(t, tc.wantID, string(req.ID), tc.name)
	}

	req, err := a2a.Decode([]byte(`{"jsonrpc":"2.0","id":"r1","method":"GetTask","params":{"id":"t-1"}}`))
	require.NoError(t, err)
	assert.Equal(t, `"r1"`, string(req.ID))
	assert.Equal(t, "GetTask", req.Method)
	assert.JSONEq(t, `{"id":"t-1"}`, string(req.Params))
}

func TestRequestContent_SendParts(t *testing.T) {
	t.Parallel()
	want := []a2a.Part{
		{Type: a2a.PartText, Text: "book a flight"},
		{Type: a2a.PartData, Data: json.RawMessage(`{"iban":"ES9121000418450200051332"}`)},
		{Type: a2a.PartFile, URL: "https://files.example.com/a.pdf", MediaType: "application/pdf", Filename: "a.pdf"},
		{Type: a2a.PartFile, Raw: "JVBERi0xLjc=", MediaType: "application/pdf", Filename: "b.pdf"},
	}
	for v, prefix := range versions {
		req := decodeFixture(t, prefix+".send.request.json")
		kind, ok := a2a.MethodKind(v, req.Method)
		require.True(t, ok)
		got, err := a2a.RequestContent(v, kind, req.Params)
		require.NoError(t, err)
		require.Len(t, got.Parts, len(want), prefix)
		for i := range want {
			assert.Equal(t, want[i].Type, got.Parts[i].Type, prefix)
			assert.Equal(t, want[i].Text, got.Parts[i].Text, prefix)
			assert.Equal(t, want[i].URL, got.Parts[i].URL, prefix)
			assert.Equal(t, want[i].Raw, got.Parts[i].Raw, prefix)
			assert.Equal(t, want[i].MediaType, got.Parts[i].MediaType, prefix)
			assert.Equal(t, want[i].Filename, got.Parts[i].Filename, prefix)
			if want[i].Data != nil {
				assert.JSONEq(t, string(want[i].Data), string(got.Parts[i].Data), prefix)
			}
		}
	}
}

func TestRequestContent_Ownership(t *testing.T) {
	t.Parallel()
	taskIDs := map[a2a.Version]string{
		a2a.Version03: "491328c6-3a34-4bfd-a3cb-0cfeaa80d2aa",
		a2a.Version10: "3cad155d-0af8-4d33-9734-4dc86c76004c",
	}
	for v, prefix := range versions {
		stream := decodeFixture(t, prefix+".stream.request.json")
		kind, _ := a2a.MethodKind(v, stream.Method)
		require.Equal(t, a2a.KindStream, kind)
		got, err := a2a.RequestContent(v, kind, stream.Params)
		require.NoError(t, err)
		assert.Equal(t, "ctx-1", got.ContextID, prefix)
		assert.Empty(t, got.TaskID, prefix)

		get := decodeFixture(t, prefix+".get.request.json")
		kind, _ = a2a.MethodKind(v, get.Method)
		require.Equal(t, a2a.KindGet, kind)
		got, err = a2a.RequestContent(v, kind, get.Params)
		require.NoError(t, err)
		assert.Equal(t, taskIDs[v], got.TaskID, prefix)
	}
}

// The agents' parsers match keys exactly and accept the snake_case name, so
// the gateway reads the ids the way the agent will.
func TestRequestContent_ReadsIDsAsTheAgentDoes(t *testing.T) {
	t.Parallel()
	got, err := a2a.RequestContent(a2a.Version10, a2a.KindSend,
		json.RawMessage(`{"message":{"taskId":"mine","TASKID":"other","context_id":"ctx","parts":[]}}`))
	require.NoError(t, err)
	assert.Equal(t, "mine", got.TaskID)
	assert.Equal(t, "ctx", got.ContextID)

	got, err = a2a.RequestContent(a2a.Version03, a2a.KindSend,
		json.RawMessage(`{"message":{"parts":[{"kind":"text","text":"evil","TEXT":"benign"}]}}`))
	require.NoError(t, err)
	require.Len(t, got.Parts, 1)
	assert.Equal(t, "evil", got.Parts[0].Text)

	got, err = a2a.RequestContent(a2a.Version10, a2a.KindSend,
		json.RawMessage(`{"message":{"parts":[{"text":null,"raw":"JVBERi0xLjc="}]}}`))
	require.NoError(t, err)
	require.Len(t, got.Parts, 1)
	assert.Equal(t, a2a.PartFile, got.Parts[0].Type)
}

func TestRequestContent_RefusesParamsWithoutIDs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		kind   a2a.Kind
		params string
	}{
		{a2a.KindSend, `{}`},
		{a2a.KindStream, `{"message":"hi"}`},
		{a2a.KindGet, `{}`},
		{a2a.KindCancel, `[]`},
		{a2a.KindSubscribe, ``},
	} {
		_, err := a2a.RequestContent(a2a.Version10, tc.kind, json.RawMessage(tc.params))
		assert.Equal(t, a2a.CodeInvalidParams, rpcCode(t, err), "%s %s", tc.kind, tc.params)
	}
}

func TestResultContent_Task(t *testing.T) {
	t.Parallel()
	states := map[a2a.Version]string{a2a.Version03: "completed", a2a.Version10: "TASK_STATE_COMPLETED"}
	ids := map[a2a.Version][2]string{
		a2a.Version03: {"491328c6-3a34-4bfd-a3cb-0cfeaa80d2aa", "a2dcdf2e-968d-4b2f-9b73-b0ea8131f238"},
		a2a.Version10: {"3cad155d-0af8-4d33-9734-4dc86c76004c", "263ba948-ae05-4d97-a610-a5f398ff2bbe"},
	}
	for v, prefix := range versions {
		got, err := a2a.ResultContent(v, resultOf(t, readFixture(t, prefix+".send.response.json")))
		require.NoError(t, err)
		assert.Equal(t, ids[v][0], got.TaskID, prefix)
		assert.Equal(t, ids[v][1], got.ContextID, prefix)
		assert.Equal(t, states[v], got.State, prefix)
		require.Len(t, got.Parts, 6, prefix)
		assert.Equal(t, "done", got.Parts[0].Text, "status message first")
		assert.Equal(t, "itinerary", got.Parts[1].Text)
		assert.JSONEq(t, `{"flight":"IB3166"}`, string(got.Parts[2].Data))
		assert.Equal(t, "https://files.example.com/ticket.pdf", got.Parts[3].URL)
		assert.Equal(t, "JVBERi0xLjc=", got.Parts[4].Raw)
		assert.Equal(t, "working on it", got.Parts[5].Text, "the agent's history message; the user's is left out")
	}
}

func TestResultContent_Message(t *testing.T) {
	t.Parallel()
	for v, prefix := range versions {
		got, err := a2a.ResultContent(v, resultOf(t, readFixture(t, prefix+".send_message_result.response.json")))
		require.NoError(t, err)
		assert.NotEmpty(t, got.ContextID, prefix)
		assert.Equal(t, []a2a.Part{{Type: a2a.PartText, Text: "hello back"}}, got.Parts, prefix)
	}
}

func TestResultContent_StreamEvents(t *testing.T) {
	t.Parallel()
	for v, prefix := range versions {
		var events []a2a.Content
		sc := bufio.NewScanner(bytes.NewReader(readFixture(t, prefix+".stream.response.sse")))
		for sc.Scan() {
			data, ok := strings.CutPrefix(sc.Text(), "data:")
			if !ok {
				continue
			}
			c, err := a2a.ResultContent(v, resultOf(t, []byte(data)))
			require.NoError(t, err, prefix)
			events = append(events, c)
		}
		require.Len(t, events, 4, prefix)
		for _, e := range events {
			assert.Equal(t, events[0].TaskID, e.TaskID, prefix)
			assert.Equal(t, "ctx-1", e.ContextID, prefix)
		}
		assert.NotEmpty(t, events[0].TaskID, prefix)
		assert.Empty(t, events[0].Parts, "the submitted task has only the user's message")
		assert.Equal(t, "working on it", events[1].Parts[0].Text, prefix)
		assert.Len(t, events[2].Parts, 4, prefix)
		assert.Equal(t, "done", events[3].Parts[0].Text, prefix)
		assert.Contains(t, strings.ToLower(events[3].State), "completed", prefix)
	}
}

func TestResultContent_RefusesWhatIsNotAResult(t *testing.T) {
	t.Parallel()
	for v := range versions {
		for _, raw := range []string{`"ok"`, `{}`, `{"kind":"nonsense"}`} {
			_, err := a2a.ResultContent(v, json.RawMessage(raw))
			assert.Equal(t, a2a.CodeGatewayFailure, rpcCode(t, err), raw)
		}
	}
}
