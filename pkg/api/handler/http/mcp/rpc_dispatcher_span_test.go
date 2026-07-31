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

package mcp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/app/mcp/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestRPCGateway_Dispatch_RecordsToolSpan(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{"content":[]}`)
	composer := mocks.NewComposer(t)
	composer.EXPECT().
		CallTool(mock.Anything, mock.Anything, "echo", mock.Anything).
		Return(raw, nil).Once()

	rt := trace.New("t-1", trace.Metadata{Kind: events.KindMCP})
	ctx := trace.NewContext(context.Background(), rt)

	g := mcphttp.NewRPCGateway(composer, noopRunner(), nil)
	_, err := g.Dispatch(ctx, &appconsumer.RoutableConsumer{}, "tools/call", json.RawMessage(`{"name":"echo"}`))
	require.NoError(t, err)

	spans := rt.Spans()
	require.Len(t, spans, 1)
	require.Equal(t, trace.SpanMCP, spans[0].Type)
	attrs, ok := spans[0].MCPAttrsCopy()
	require.True(t, ok)
	assert.Equal(t, "tools/call", attrs.Method)
	assert.Equal(t, "tool", attrs.Operation)
	assert.Equal(t, "echo", attrs.Tool)
	assert.Equal(t, http.StatusOK, attrs.UpstreamStatus)
}

func TestRPCGateway_Dispatch_RecordsErrorStatus(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().
		ListTools(mock.Anything, mock.Anything).
		Return(nil, assertErr{}).Once()

	rt := trace.New("t-2", trace.Metadata{Kind: events.KindMCP})
	ctx := trace.NewContext(context.Background(), rt)

	g := mcphttp.NewRPCGateway(composer, noopRunner(), nil)
	_, err := g.Dispatch(ctx, &appconsumer.RoutableConsumer{}, "tools/list", nil)
	require.Error(t, err)

	spans := rt.Spans()
	require.Len(t, spans, 1)
	attrs, ok := spans[0].MCPAttrsCopy()
	require.True(t, ok)
	assert.Equal(t, "discovery", attrs.Operation)
	assert.Equal(t, http.StatusBadGateway, attrs.UpstreamStatus)
}

func TestRPCGateway_Dispatch_RecordsPolicyBlockedHTTPStatus(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().
		CallTool(mock.Anything, mock.Anything, "echo", mock.Anything).
		Return(nil, &appmcp.RPCError{
			Code:       -32001,
			Message:    "blocked",
			HTTPStatus: http.StatusForbidden,
		}).Once()

	rt := trace.New("t-3", trace.Metadata{Kind: events.KindMCP})
	ctx := trace.NewContext(context.Background(), rt)

	g := mcphttp.NewRPCGateway(composer, noopRunner(), nil)
	_, err := g.Dispatch(ctx, &appconsumer.RoutableConsumer{}, "tools/call", json.RawMessage(`{"name":"echo"}`))
	require.Error(t, err)

	attrs, ok := rt.Spans()[0].MCPAttrsCopy()
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, attrs.UpstreamStatus)
	assert.Equal(t, -32001, attrs.RPCErrorCode)
}

// An upstream the user has not connected yet is an authorization gap, not a
// broken gateway: recording it as 502 hid real upstream failures among routine
// consent prompts.
func TestRPCGateway_Dispatch_RecordsConsentAsForbidden(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().
		CallTool(mock.Anything, mock.Anything, "notion-search", mock.Anything).
		Return(nil, &appmcp.ConsentRequiredError{
			Provider: "com.notion/mcp", Ticket: "tk", Path: "/p/mcp",
		}).Once()

	rt := trace.New("t-4", trace.Metadata{Kind: events.KindMCP})
	ctx := trace.NewContext(context.Background(), rt)

	g := mcphttp.NewRPCGateway(composer, noopRunner(), nil)
	_, err := g.Dispatch(ctx, &appconsumer.RoutableConsumer{}, "tools/call",
		json.RawMessage(`{"name":"notion-search"}`))
	require.Error(t, err)

	attrs, ok := rt.Spans()[0].MCPAttrsCopy()
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, attrs.UpstreamStatus)
	assert.Equal(t, -32003, attrs.RPCErrorCode)
}

type assertErr struct{}

func (assertErr) Error() string { return "boom" }

