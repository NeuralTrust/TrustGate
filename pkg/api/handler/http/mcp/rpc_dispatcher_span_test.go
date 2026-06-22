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
	"testing"

	mcphttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/app/mcp/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/events"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/trace"
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

	g := mcphttp.NewRPCGateway(composer)
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
	assert.Equal(t, "ok", attrs.UpstreamStatus)
}

func TestRPCGateway_Dispatch_RecordsErrorStatus(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().
		ListTools(mock.Anything, mock.Anything).
		Return(nil, assertErr{}).Once()

	rt := trace.New("t-2", trace.Metadata{Kind: events.KindMCP})
	ctx := trace.NewContext(context.Background(), rt)

	g := mcphttp.NewRPCGateway(composer)
	_, err := g.Dispatch(ctx, &appconsumer.RoutableConsumer{}, "tools/list", nil)
	require.Error(t, err)

	spans := rt.Spans()
	require.Len(t, spans, 1)
	attrs, ok := spans[0].MCPAttrsCopy()
	require.True(t, ok)
	assert.Equal(t, "discovery", attrs.Operation)
	assert.Equal(t, "error", attrs.UpstreamStatus)
}

type assertErr struct{}

func (assertErr) Error() string { return "boom" }
