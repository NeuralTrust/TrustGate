package client

import (
	"encoding/json"
	"errors"
	"fmt"

	appmcp "github.com/NeuralTrust/AgentGateway/pkg/app/mcp"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

func wrapUnreachable(url string, err error) error {
	return fmt.Errorf("%w: %s: %w", appmcp.ErrUnreachable, url, err)
}

func mapRPCError(err error) error {
	if err == nil {
		return nil
	}
	var je *jsonrpc.Error
	if errors.As(err, &je) {
		return &appmcp.RPCError{Code: je.Code, Message: je.Message, Data: je.Data}
	}
	return err
}

func mapItems[T any](method string, items any) ([]T, error) {
	raw, err := json.Marshal(items)
	if err != nil {
		return nil, fmt.Errorf("mcp client: %s: encode items: %w", method, err)
	}
	var out []T
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("mcp client: %s: map items: %w", method, err)
	}
	return out, nil
}
