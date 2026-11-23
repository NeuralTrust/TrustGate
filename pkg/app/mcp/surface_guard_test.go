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

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// surfaceMasker masks a word in the request body and in every text and
// embedded resource block of the response, as TrustGuard's DLP would, and
// records what each stage was shown.
type surfaceMasker struct {
	from, to string
	request  []byte
	response []byte
	block    policydomain.Stage
	extra    bool
}

func (e *surfaceMasker) RunStage(_ context.Context, in appplugins.StageInput) (*appplugins.StageOutcome, error) {
	if e.block == in.Stage {
		return nil, &appplugins.PluginError{StatusCode: http.StatusForbidden, Message: "blocked"}
	}
	if in.Stage == policydomain.StagePreRequest {
		e.request = append([]byte(nil), in.Request.Body...)
		in.Request.Body = []byte(strings.ReplaceAll(string(in.Request.Body), e.from, e.to))
		return &appplugins.StageOutcome{}, nil
	}
	e.response = append([]byte(nil), in.Response.Body...)
	if !strings.Contains(string(in.Response.Body), e.from) {
		return &appplugins.StageOutcome{}, nil
	}
	body := strings.ReplaceAll(string(in.Response.Body), e.from, e.to)
	if e.extra {
		body = strings.Replace(body, `"content":[`, `"content":[{"type":"text","text":"x"},`, 1)
	}
	return &appplugins.StageOutcome{ShortCircuit: true, StatusCode: http.StatusOK, Body: []byte(body)}, nil
}

func surfaceDispatcher(t *testing.T, exec appplugins.Executor, result string) (*RPCDispatcher, *fakeUpstream, string, func(method string, params string) (any, error)) {
	t.Helper()
	reg := mcpRegistry(t, "docs", "https://docs.example.com/mcp")
	up := &fakeUpstream{
		prompts:   []Prompt{{Name: "summarize"}},
		resources: []Resource{{Name: "readme", URI: "repo://docs/readme"}},
		result:    json.RawMessage(result),
	}
	composer := newTestComposer(&fakeDialer{upstreams: map[string]*fakeUpstream{"https://docs.example.com/mcp": up}})
	d := NewRPCDispatcher(composer, NewPluginRunner(exec, discardLogger()), nil, nil, nil)
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, reg)
	call := func(method, params string) (any, error) {
		return d.Dispatch(context.Background(), rc, "", method, json.RawMessage(params))
	}
	return d, up, namedFor(reg, "summarize"), call
}

const promptResult = `{"description":"Summarize for jane@acme.io","messages":[` +
	`{"role":"user","content":{"type":"text","text":"Write to jane@acme.io <now>"}},` +
	`{"role":"assistant","content":{"type":"resource","resource":{"uri":"repo://x","mimeType":"text/plain","text":"jane@acme.io wrote this"}}},` +
	`{"role":"user","content":{"type":"image","data":"aGk=","mimeType":"image/png"}}]}`

func TestGetPrompt_RunsBothStagesAndWritesMasksBack(t *testing.T) {
	t.Parallel()
	masker := &surfaceMasker{from: "jane@acme.io", to: "[EMAIL]"}
	_, up, name, call := surfaceDispatcher(t, masker, promptResult)

	res, err := call("prompts/get", `{"name":"`+name+`","arguments":{"to":"jane@acme.io","tone":"short"}}`)
	require.NoError(t, err)

	assert.JSONEq(t, `{"name":"`+name+`","arguments":{"to":"jane@acme.io","tone":"short"}}`, string(masker.request),
		"the request stage sees the prompt as a tool call")
	assert.Equal(t, map[string]string{"to": "[EMAIL]", "tone": "short"}, up.lastArgs, "masked arguments reach the server")

	assert.JSONEq(t, `{"content":[`+
		`{"type":"text","text":"Summarize for jane@acme.io"},`+
		`{"type":"text","text":"Write to jane@acme.io <now>"},`+
		`{"type":"resource","resource":{"uri":"repo://x","mimeType":"text/plain","text":"jane@acme.io wrote this"}}]}`,
		string(masker.response), "the response stage sees the prompt's text as a tool result")

	out := string(res.(json.RawMessage))
	assert.NotContains(t, out, "jane@acme.io")
	assert.JSONEq(t, strings.ReplaceAll(promptResult, "jane@acme.io", "[EMAIL]"), out)
	assert.Contains(t, out, "<now>", "no HTML escaping on the way back")
}

func TestGetPrompt_UnmaskedResultIsRelayedAsItCame(t *testing.T) {
	t.Parallel()
	masker := &surfaceMasker{from: "nobody@else", to: "x"}
	_, _, name, call := surfaceDispatcher(t, masker, promptResult)
	res, err := call("prompts/get", `{"name":"`+name+`"}`)
	require.NoError(t, err)
	assert.Equal(t, promptResult, string(res.(json.RawMessage)))
}

func TestGetPrompt_PolicyBlocks(t *testing.T) {
	t.Parallel()
	for _, stage := range []policydomain.Stage{policydomain.StagePreRequest, policydomain.StagePreResponse} {
		masker := &surfaceMasker{from: "a", to: "b", block: stage}
		_, up, name, call := surfaceDispatcher(t, masker, promptResult)
		_, err := call("prompts/get", `{"name":"`+name+`"}`)
		var rpcErr *RPCError
		require.True(t, errors.As(err, &rpcErr), "%s: %v", stage, err)
		assert.Equal(t, CodePolicyBlocked, rpcErr.Code)
		if stage == policydomain.StagePreRequest {
			assert.Empty(t, up.lastPrompt, "a refused request never reaches the server")
		}
	}
}

func TestGetPrompt_MaskThatCannotBeWrittenBackRefuses(t *testing.T) {
	t.Parallel()
	masker := &surfaceMasker{from: "jane@acme.io", to: "[EMAIL]", extra: true}
	_, _, name, call := surfaceDispatcher(t, masker, promptResult)
	_, err := call("prompts/get", `{"name":"`+name+`"}`)
	var rpcErr *RPCError
	require.True(t, errors.As(err, &rpcErr), "%v", err)
	assert.Equal(t, CodePolicyBlocked, rpcErr.Code)
}

func TestGetPrompt_CannedReplyIsARefusal(t *testing.T) {
	t.Parallel()
	_, up, name, call := surfaceDispatcher(t, &replyExecutor{body: []byte(`{"content":[]}`)}, promptResult)
	_, err := call("prompts/get", `{"name":"`+name+`"}`)
	var rpcErr *RPCError
	require.True(t, errors.As(err, &rpcErr), "%v", err)
	assert.Empty(t, up.lastPrompt)
}

func TestReadResource_InspectsTextAndKeepsTheURI(t *testing.T) {
	t.Parallel()
	const result = `{"contents":[` +
		`{"uri":"repo://docs/readme","mimeType":"text/markdown","text":"Contact jane@acme.io"},` +
		`{"uri":"repo://docs/logo","mimeType":"image/png","blob":"aGk="}]}`
	masker := &surfaceMasker{from: "docs", to: "[MASKED]"}
	_, up, _, call := surfaceDispatcher(t, masker, result)

	res, err := call("resources/read", `{"uri":"repo://docs/readme"}`)
	require.NoError(t, err)
	assert.JSONEq(t, `{"name":"resources/read","arguments":{"uri":"repo://docs/readme"}}`, string(masker.request))
	assert.Equal(t, "repo://docs/readme", up.lastRead, "a mask of the URI is dropped: it is an address")
	assert.JSONEq(t, `{"content":[{"type":"resource","resource":{"uri":"repo://docs/readme","mimeType":"text/markdown","text":"Contact jane@acme.io"}}]}`,
		string(masker.response), "only text contents are shown; a blob has none")
	out := string(res.(json.RawMessage))
	assert.Contains(t, out, `"blob":"aGk="`)
	assert.Contains(t, out, `"uri":"repo://docs/readme"`, "a mask written back touches only the text")
}

func TestReadResource_MaskedText(t *testing.T) {
	t.Parallel()
	const result = `{"contents":[{"uri":"repo://docs/readme","text":"Contact jane@acme.io"}]}`
	masker := &surfaceMasker{from: "jane@acme.io", to: "[EMAIL]"}
	_, _, _, call := surfaceDispatcher(t, masker, result)
	res, err := call("resources/read", `{"uri":"repo://docs/readme"}`)
	require.NoError(t, err)
	assert.JSONEq(t, `{"contents":[{"uri":"repo://docs/readme","text":"Contact [EMAIL]"}]}`, string(res.(json.RawMessage)))
}

func TestSurface_NoPluginsRelaysAsItCame(t *testing.T) {
	t.Parallel()
	_, _, name, call := surfaceDispatcher(t, nil, promptResult)
	res, err := call("prompts/get", `{"name":"`+name+`"}`)
	require.NoError(t, err)
	assert.Equal(t, promptResult, string(res.(json.RawMessage)))
}
