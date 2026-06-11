// Package client dials upstream MCP servers through the official MCP Go SDK
// (Streamable HTTP transport). It exposes the protocol surface the gateway
// federates - tools, resources, resource templates, and prompts - returning
// list results as typed values (for composition) and call/read/get results as
// raw JSON (forwarded to the gateway's own client verbatim).
//
// Elicitation and sampling handlers are intentionally not registered: the
// gateway's server plane answers single JSON-RPC responses and cannot relay
// server-initiated requests back to the end client. By not advertising those
// capabilities, spec-compliant upstreams degrade gracefully instead of
// hanging mid-call.
package client

import (
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Type aliases keep the rest of the codebase decoupled from the SDK import
// path; all of them marshal to the spec JSON shape.
type (
	Tool             = sdk.Tool
	Resource         = sdk.Resource
	ResourceTemplate = sdk.ResourceTemplate
	Prompt           = sdk.Prompt
)

// RPCError is a JSON-RPC error returned by an upstream MCP server; the
// gateway passes it through to its own client unchanged.
type RPCError = jsonrpc.Error

// ErrUnreachable wraps transport-level failures so callers can distinguish
// "upstream down" from protocol errors (drives consumer fail_mode).
var ErrUnreachable = errors.New("mcp upstream unreachable")

// ErrNotSupported means the upstream did not advertise the capability needed
// by the requested method (e.g. resources/read on a tools-only server).
var ErrNotSupported = errors.New("mcp upstream does not support this method")

// IsRPCError reports whether err is an application-level JSON-RPC error from
// the upstream (the request was processed), as opposed to a transport or
// session failure (the request may not have reached the server).
func IsRPCError(err error) bool {
	var rpcErr *RPCError
	return errors.As(err, &rpcErr)
}

func wrapUnreachable(url string, err error) error {
	return fmt.Errorf("%w: %s: %w", ErrUnreachable, url, err)
}
