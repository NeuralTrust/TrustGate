// Package client dials upstream MCP servers through the official MCP Go SDK
// (Streamable HTTP transport). It implements the app-layer mcp.Dialer and
// mcp.Upstream ports: list results are mapped from SDK values to the
// app-owned protocol envelopes, and call/read/get results stay raw JSON
// (forwarded to the gateway's own client verbatim).
//
// Elicitation and sampling handlers are intentionally not registered: the
// gateway's server plane answers single JSON-RPC responses and cannot relay
// server-initiated requests back to the end client. By not advertising those
// capabilities, spec-compliant upstreams degrade gracefully instead of
// hanging mid-call.
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

// mapRPCError converts the SDK's JSON-RPC errors into the app-owned
// mcp.RPCError so upper layers never depend on the SDK import path.
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

// mapItems converts SDK protocol values into app envelopes via their shared
// spec JSON shape, so every field the upstream sent survives the proxy.
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
