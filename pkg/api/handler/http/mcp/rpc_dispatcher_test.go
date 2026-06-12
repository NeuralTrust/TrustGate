package mcp_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	mcphttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/app/mcp/mocks"
	"github.com/stretchr/testify/mock"
)

func TestRPCGateway_ToolsList_DefaultsToEmptySlice(t *testing.T) {
	t.Parallel()
	composer := mocks.NewComposer(t)
	composer.EXPECT().ListTools(mock.Anything, mock.Anything).Return(nil, nil).Once()

	g := mcphttp.NewRPCGateway(composer)
	res, err := g.Dispatch(context.Background(), &appconsumer.RoutableConsumer{}, "tools/list", nil)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	body, _ := json.Marshal(res)
	if string(body) != `{"tools":[]}` {
		t.Fatalf("tools/list = %s, want empty array (clients reject null)", body)
	}
}

func TestRPCGateway_ToolsCall_RequiresName(t *testing.T) {
	t.Parallel()
	g := mcphttp.NewRPCGateway(mocks.NewComposer(t))
	_, err := g.Dispatch(context.Background(), &appconsumer.RoutableConsumer{}, "tools/call", json.RawMessage(`{}`))
	var invalid *mcphttp.InvalidParamsError
	if !errors.As(err, &invalid) {
		t.Fatalf("error = %v, want mcphttp.InvalidParamsError", err)
	}
}

func TestRPCGateway_ToolsCall_ForwardsRawResult(t *testing.T) {
	t.Parallel()
	raw := json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)
	composer := mocks.NewComposer(t)
	composer.EXPECT().
		CallTool(mock.Anything, mock.Anything, "echo", mock.Anything).
		Return(raw, nil).Once()

	g := mcphttp.NewRPCGateway(composer)
	res, err := g.Dispatch(context.Background(), &appconsumer.RoutableConsumer{}, "tools/call", json.RawMessage(`{"name":"echo"}`))
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	got, ok := res.(json.RawMessage)
	if !ok || string(got) != string(raw) {
		t.Fatalf("result = %#v, want verbatim raw payload", res)
	}
}

func TestRPCGateway_ResourcesRead_RequiresURI(t *testing.T) {
	t.Parallel()
	g := mcphttp.NewRPCGateway(mocks.NewComposer(t))
	_, err := g.Dispatch(context.Background(), &appconsumer.RoutableConsumer{}, "resources/read", json.RawMessage(`{}`))
	var invalid *mcphttp.InvalidParamsError
	if !errors.As(err, &invalid) {
		t.Fatalf("error = %v, want mcphttp.InvalidParamsError", err)
	}
}

func TestRPCGateway_UnknownMethod(t *testing.T) {
	t.Parallel()
	g := mcphttp.NewRPCGateway(mocks.NewComposer(t))
	_, err := g.Dispatch(context.Background(), &appconsumer.RoutableConsumer{}, "tools/subscribe", nil)
	if !errors.Is(err, mcphttp.ErrMethodNotFound) {
		t.Fatalf("error = %v, want mcphttp.ErrMethodNotFound", err)
	}
}

func TestRPCGateway_PromptsGet_RequiresName(t *testing.T) {
	t.Parallel()
	g := mcphttp.NewRPCGateway(mocks.NewComposer(t))
	_, err := g.Dispatch(context.Background(), &appconsumer.RoutableConsumer{}, "prompts/get", json.RawMessage(`{"arguments":{}}`))
	var invalid *mcphttp.InvalidParamsError
	if !errors.As(err, &invalid) {
		t.Fatalf("error = %v, want mcphttp.InvalidParamsError", err)
	}
}
