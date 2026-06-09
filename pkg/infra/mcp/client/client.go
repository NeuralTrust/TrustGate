package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

const (
	clientName     = "agentgateway"
	clientVersion  = "1.0"
	defaultTimeout = 30 * time.Second
	maxBodyBytes   = 16 << 20 // 16 MiB
)

// ErrUnreachable wraps transport-level failures so callers can distinguish
// "upstream down" from protocol errors (drives consumer fail_mode).
var ErrUnreachable = errors.New("mcp upstream unreachable")

// ErrSessionExpired means the upstream no longer recognizes the session id
// (HTTP 404 per the Streamable HTTP spec); callers should re-initialize.
var ErrSessionExpired = errors.New("mcp upstream session expired")

// Target identifies one upstream MCP server endpoint.
type Target struct {
	URL string
	// Headers are sent on every request (static auth, custom headers).
	Headers map[string]string
	// PinKey, when set, lets session-pinning dialers persist and resume the
	// upstream Mcp-Session-Id across replicas.
	PinKey string
}

// Client dials upstream MCP servers over Streamable HTTP.
type Client struct {
	http *http.Client
}

func New() *Client {
	return &Client{http: &http.Client{Timeout: defaultTimeout}}
}

// Session is an initialized MCP connection to one upstream server.
type Session struct {
	client    *Client
	target    Target
	sessionID string
	protocol  string
	nextID    atomic.Int64
}

// Connect performs the initialize handshake and the initialized notification.
func (c *Client) Connect(ctx context.Context, target Target) (*Session, error) {
	s := &Session{client: c, target: target, protocol: ProtocolVersion}
	var res initializeResult
	httpRes, err := s.call(ctx, "initialize", initializeParams{
		ProtocolVersion: ProtocolVersion,
		Capabilities:    map[string]any{},
		ClientInfo:      implementation{Name: clientName, Version: clientVersion},
	}, &res)
	if err != nil {
		return nil, err
	}
	if sid := httpRes.Header.Get(headerSessionID); sid != "" {
		s.sessionID = sid
	}
	if res.ProtocolVersion != "" {
		s.protocol = res.ProtocolVersion
	}
	if err := s.notify(ctx, "notifications/initialized"); err != nil {
		return nil, err
	}
	return s, nil
}

// Resume rebuilds a session from previously stored pin data, skipping the
// initialize handshake. If the upstream expired the session, the next request
// fails with ErrSessionExpired.
func (c *Client) Resume(target Target, sessionID, protocol string) *Session {
	if protocol == "" {
		protocol = ProtocolVersion
	}
	return &Session{client: c, target: target, sessionID: sessionID, protocol: protocol}
}

// SessionID returns the upstream-issued session id (empty for stateless upstreams).
func (s *Session) SessionID() string { return s.sessionID }

// Protocol returns the negotiated MCP protocol version.
func (s *Session) Protocol() string { return s.protocol }

// ListTools fetches all tools, following pagination cursors.
func (s *Session) ListTools(ctx context.Context) ([]Tool, error) {
	var out []Tool
	cursor := ""
	for {
		var res listToolsResult
		if _, err := s.call(ctx, "tools/list", listToolsParams{Cursor: cursor}, &res); err != nil {
			return nil, err
		}
		out = append(out, res.Tools...)
		if res.NextCursor == "" {
			return out, nil
		}
		cursor = res.NextCursor
	}
}

// CallTool invokes a tool and returns the raw CallToolResult, which the
// gateway forwards to its own client verbatim.
func (s *Session) CallTool(ctx context.Context, name string, arguments json.RawMessage) (json.RawMessage, error) {
	var res json.RawMessage
	if _, err := s.call(ctx, "tools/call", callToolParams{Name: name, Arguments: arguments}, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// Ping checks upstream liveness.
func (s *Session) Ping(ctx context.Context) error {
	var res json.RawMessage
	_, err := s.call(ctx, "ping", struct{}{}, &res)
	return err
}

// Close terminates the upstream session (best effort).
func (s *Session) Close(ctx context.Context) {
	if s.sessionID == "" {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.target.URL, nil)
	if err != nil {
		return
	}
	s.setHeaders(req)
	res, err := s.client.http.Do(req)
	if err != nil {
		return
	}
	_ = res.Body.Close()
}

func (s *Session) call(ctx context.Context, method string, params, result any) (*http.Response, error) {
	id := s.nextID.Add(1)
	httpRes, body, err := s.post(ctx, jsonrpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	if err != nil {
		return nil, err
	}
	rpcRes, err := decodeResponse(httpRes, body, id)
	if err != nil {
		return nil, fmt.Errorf("mcp client: %s: %w", method, err)
	}
	if rpcRes.Error != nil {
		return nil, rpcRes.Error
	}
	if result != nil {
		if err := json.Unmarshal(rpcRes.Result, result); err != nil {
			return nil, fmt.Errorf("mcp client: %s: decode result: %w", method, err)
		}
	}
	return httpRes, nil
}

func (s *Session) notify(ctx context.Context, method string) error {
	res, _, err := s.post(ctx, jsonrpcRequest{JSONRPC: "2.0", Method: method})
	if err != nil {
		return err
	}
	// Notifications expect 202 Accepted; tolerate any 2xx.
	if res.StatusCode >= 300 {
		return fmt.Errorf("mcp client: %s: unexpected status %d", method, res.StatusCode)
	}
	return nil
}

func (s *Session) post(ctx context.Context, payload jsonrpcRequest) (*http.Response, []byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("mcp client: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.target.URL, bytes.NewReader(raw))
	if err != nil {
		return nil, nil, fmt.Errorf("mcp client: build request: %w", err)
	}
	s.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	res, err := s.client.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s: %w", ErrUnreachable, s.target.URL, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBodyBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s: read body: %w", ErrUnreachable, s.target.URL, err)
	}
	if res.StatusCode >= 500 {
		return nil, nil, fmt.Errorf("%w: %s: status %d", ErrUnreachable, s.target.URL, res.StatusCode)
	}
	if res.StatusCode == http.StatusNotFound && s.sessionID != "" {
		return nil, nil, fmt.Errorf("%w: %s", ErrSessionExpired, s.target.URL)
	}
	if res.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("mcp client: %s: status %d: %s", s.target.URL, res.StatusCode, truncate(body, 256))
	}
	return res, body, nil
}

func (s *Session) setHeaders(req *http.Request) {
	for k, v := range s.target.Headers {
		req.Header.Set(k, v)
	}
	if s.sessionID != "" {
		req.Header.Set(headerSessionID, s.sessionID)
	}
	if s.protocol != "" {
		req.Header.Set(headerProtocolVersion, s.protocol)
	}
}

// decodeResponse handles both plain JSON and SSE response bodies, returning
// the JSON-RPC response that matches the request id.
func decodeResponse(res *http.Response, body []byte, wantID int64) (*jsonrpcResponse, error) {
	contentType := res.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "text/event-stream") {
		return decodeSSE(body, wantID)
	}
	var rpcRes jsonrpcResponse
	if err := json.Unmarshal(body, &rpcRes); err != nil {
		return nil, fmt.Errorf("decode json response: %w", err)
	}
	return &rpcRes, nil
}

func decodeSSE(body []byte, wantID int64) (*jsonrpcResponse, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 64*1024), maxBodyBytes)
	var data strings.Builder
	flush := func() (*jsonrpcResponse, bool) {
		if data.Len() == 0 {
			return nil, false
		}
		payload := data.String()
		data.Reset()
		var rpcRes jsonrpcResponse
		if err := json.Unmarshal([]byte(payload), &rpcRes); err != nil {
			return nil, false // skip non-JSON-RPC events
		}
		if rpcRes.Method != "" {
			return nil, false // server-initiated notification/request; ignore
		}
		var id int64
		if err := json.Unmarshal(rpcRes.ID, &id); err != nil || id != wantID {
			return nil, false
		}
		return &rpcRes, true
	}
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			if rpcRes, ok := flush(); ok {
				return rpcRes, nil
			}
		case strings.HasPrefix(line, "data:"):
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan sse stream: %w", err)
	}
	if rpcRes, ok := flush(); ok {
		return rpcRes, nil
	}
	return nil, errors.New("sse stream ended without a matching response")
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
