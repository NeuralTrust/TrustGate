package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// The gateway only manipulates a handful of protocol fields (names for
// rename/collision handling, URIs for routing); everything else an upstream
// returns is carried opaquely in payload and re-emitted verbatim, so new spec
// fields survive the proxy without code changes and the app layer stays
// independent of the MCP SDK.

// Tool is one tool of a (virtual) MCP server's surface.
type Tool struct {
	Name string

	payload map[string]json.RawMessage
}

func (t Tool) MarshalJSON() ([]byte, error) {
	return marshalEnvelope(t.payload, "name", t.Name)
}

func (t *Tool) UnmarshalJSON(data []byte) error {
	payload, err := unmarshalEnvelope(data)
	if err != nil {
		return fmt.Errorf("mcp: decode tool: %w", err)
	}
	t.payload = payload
	t.Name = stringField(payload, "name")
	return nil
}

// Prompt is one prompt of a (virtual) MCP server's surface.
type Prompt struct {
	Name string

	payload map[string]json.RawMessage
}

func (p Prompt) MarshalJSON() ([]byte, error) {
	return marshalEnvelope(p.payload, "name", p.Name)
}

func (p *Prompt) UnmarshalJSON(data []byte) error {
	payload, err := unmarshalEnvelope(data)
	if err != nil {
		return fmt.Errorf("mcp: decode prompt: %w", err)
	}
	p.payload = payload
	p.Name = stringField(payload, "name")
	return nil
}

// Resource is one resource of a (virtual) MCP server's surface.
type Resource struct {
	Name string
	URI  string

	payload map[string]json.RawMessage
}

func (r Resource) MarshalJSON() ([]byte, error) {
	return marshalEnvelope(r.payload, "name", r.Name, "uri", r.URI)
}

func (r *Resource) UnmarshalJSON(data []byte) error {
	payload, err := unmarshalEnvelope(data)
	if err != nil {
		return fmt.Errorf("mcp: decode resource: %w", err)
	}
	r.payload = payload
	r.Name = stringField(payload, "name")
	r.URI = stringField(payload, "uri")
	return nil
}

// ResourceTemplate is one RFC 6570 resource template of a (virtual) MCP
// server's surface.
type ResourceTemplate struct {
	Name        string
	URITemplate string

	payload map[string]json.RawMessage
}

func (rt ResourceTemplate) MarshalJSON() ([]byte, error) {
	return marshalEnvelope(rt.payload, "name", rt.Name, "uriTemplate", rt.URITemplate)
}

func (rt *ResourceTemplate) UnmarshalJSON(data []byte) error {
	payload, err := unmarshalEnvelope(data)
	if err != nil {
		return fmt.Errorf("mcp: decode resource template: %w", err)
	}
	rt.payload = payload
	rt.Name = stringField(payload, "name")
	rt.URITemplate = stringField(payload, "uriTemplate")
	return nil
}

func unmarshalEnvelope(data []byte) (map[string]json.RawMessage, error) {
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// marshalEnvelope re-emits the opaque payload with the gateway-managed
// fields (given as key/value pairs) overriding whatever the upstream sent.
// The shared payload map is never mutated: envelopes are copied by value and
// may share it.
func marshalEnvelope(payload map[string]json.RawMessage, kv ...string) ([]byte, error) {
	out := make(map[string]json.RawMessage, len(payload)+len(kv)/2)
	for k, v := range payload {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		encoded, err := json.Marshal(kv[i+1])
		if err != nil {
			return nil, err
		}
		out[kv[i]] = encoded
	}
	return json.Marshal(out)
}

func stringField(payload map[string]json.RawMessage, key string) string {
	raw, ok := payload[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// Target identifies one upstream MCP server endpoint.
type Target struct {
	URL string
	// Headers are sent on every request (static auth, custom headers).
	Headers map[string]string
	// PinKey, when set, lets session-caching dialers reuse one initialized
	// upstream session across requests (scoped per principal for per-user
	// downstream auth modes).
	PinKey string
}

// RPCError is an application-level JSON-RPC error returned by an upstream
// MCP server; the gateway passes it through to its own client unchanged.
type RPCError struct {
	Code    int64           `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message)
}

// IsRPCError reports whether err is an application-level JSON-RPC error from
// the upstream (the request was processed), as opposed to a transport or
// session failure (the request may not have reached the server).
func IsRPCError(err error) bool {
	var rpcErr *RPCError
	return errors.As(err, &rpcErr)
}

// ErrUnreachable wraps transport-level failures so callers can distinguish
// "upstream down" from protocol errors (drives consumer fail_mode).
var ErrUnreachable = errors.New("mcp upstream unreachable")

// ErrNotSupported means the upstream did not advertise the capability needed
// by the requested method (e.g. resources/read on a tools-only server).
var ErrNotSupported = errors.New("mcp upstream does not support this method")

// Upstream is one initialized connection to an upstream MCP server.
type Upstream interface {
	ListTools(ctx context.Context) ([]Tool, error)
	CallTool(ctx context.Context, name string, arguments json.RawMessage) (json.RawMessage, error)
	ListResources(ctx context.Context) ([]Resource, error)
	ListResourceTemplates(ctx context.Context) ([]ResourceTemplate, error)
	ReadResource(ctx context.Context, uri string) (json.RawMessage, error)
	ListPrompts(ctx context.Context) ([]Prompt, error)
	GetPrompt(ctx context.Context, name string, arguments map[string]string) (json.RawMessage, error)
	SupportsResources() bool
	SupportsPrompts() bool
	Close(ctx context.Context)
}

// Dialer opens connections to upstream MCP servers.
type Dialer interface {
	Connect(ctx context.Context, target Target) (Upstream, error)
}

// DialerFunc adapts a function to the Dialer interface.
type DialerFunc func(ctx context.Context, target Target) (Upstream, error)

func (f DialerFunc) Connect(ctx context.Context, target Target) (Upstream, error) {
	return f(ctx, target)
}
