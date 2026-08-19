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

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/version"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	maxModernPages             = 100
	maxModernItems             = 10_000
	maxModernResponseMessages  = 100
	maxModernResponseBodyBytes = int64(sdk.DefaultMaxRequestBodyBytes)
)

var (
	errModernCursorCycle    = errors.New("mcp modern pagination cursor cycle")
	errModernPageLimit      = errors.New("mcp modern pagination page limit exceeded")
	errModernItemLimit      = errors.New("mcp modern pagination item limit exceeded")
	errModernSession        = errors.New("mcp modern response attempted to establish a session")
	errModernHTTPMethod     = errors.New("mcp modern transport only permits POST")
	errModernResponseID     = errors.New("mcp modern response ID mismatch")
	errModernMessageType    = errors.New("mcp modern received an unexpected message type")
	errModernResponseLimit  = errors.New("mcp modern response message limit exceeded")
	errModernBodyLimit      = errors.New("mcp modern response body limit exceeded")
	errModernProtocolAbsent = errors.New("mcp modern protocol version is empty")
)

type modernUpstream struct {
	target                appmcp.Target
	origin                string
	protocolVersion       string
	implementationVersion string
	httpClient            *http.Client
	nextID                atomic.Uint64
	eraCandidates         sync.Map
}

var _ appmcp.Upstream = (*modernUpstream)(nil)

func newModernUpstream(target appmcp.Target, protocolVersion string) (*modernUpstream, error) {
	return newModernUpstreamWithTransport(
		target,
		protocolVersion,
		sharedHTTPTransport,
		version.Version,
	)
}

func newModernUpstreamWithTransport(
	target appmcp.Target,
	protocolVersion string,
	transport http.RoundTripper,
	implementationVersion string,
) (*modernUpstream, error) {
	origin, err := canonicalOrigin(target.URL)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid upstream endpoint: %w", appmcp.ErrUnreachable, err)
	}
	if protocolVersion == "" {
		return nil, fmt.Errorf("%w: %w", appmcp.ErrProtocolIncompatible, errModernProtocolAbsent)
	}
	httpClient, err := newTargetHTTPClientWithTransport(target.Headers, transport)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid upstream HTTP configuration: %w", appmcp.ErrUnreachable, err)
	}
	httpClient.Transport = &modernRoundTripper{
		transport:             httpClient.Transport,
		protocolVersion:       protocolVersion,
		implementationVersion: implementationVersion,
	}
	upstream := &modernUpstream{
		target:                target,
		origin:                origin,
		protocolVersion:       protocolVersion,
		implementationVersion: implementationVersion,
		httpClient:            httpClient,
	}
	httpClient.Transport.(*modernRoundTripper).eraCandidates = &upstream.eraCandidates
	return upstream, nil
}

type modernRoundTripper struct {
	transport             http.RoundTripper
	protocolVersion       string
	implementationVersion string
	eraCandidates         *sync.Map
}

func (t *modernRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPost {
		return nil, errModernHTTPMethod
	}
	cloned := req.Clone(req.Context())
	cloned.Header = req.Header.Clone()
	cloned.Header.Set("Mcp-Protocol-Version", t.protocolVersion)
	cloned.Header.Set("User-Agent", clientName+"/"+t.implementationVersion)
	setModernRoutingHeaders(cloned)
	resp, err := t.transport.RoundTrip(cloned)
	if err != nil {
		return nil, err
	}
	if resp.Header.Get("Mcp-Session-Id") != "" {
		closeErr := resp.Body.Close()
		return nil, errors.Join(errModernSession, closeErr)
	}
	if resp.ContentLength > maxModernResponseBodyBytes {
		closeErr := resp.Body.Close()
		return nil, errors.Join(errModernBodyLimit, closeErr)
	}
	resp.Body = newBoundedModernResponseBody(resp.Body)
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusNotFound {
		return resp, nil
	}
	normalized, candidate, err := normalizeModernRPCErrorResponse(cloned, resp)
	if candidate && t.eraCandidates != nil {
		if requestID, ok := modernRequestID(cloned); ok {
			t.eraCandidates.Store(string(requestID), struct{}{})
		}
	}
	return normalized, err
}

type boundedModernResponseBody struct {
	body      io.ReadCloser
	remaining int64
	closeOnce sync.Once
	closeErr  error
}

func newBoundedModernResponseBody(body io.ReadCloser) *boundedModernResponseBody {
	return &boundedModernResponseBody{body: body, remaining: maxModernResponseBodyBytes}
}

func (b *boundedModernResponseBody) Read(p []byte) (int, error) {
	if b.remaining > 0 {
		if int64(len(p)) > b.remaining {
			p = p[:b.remaining]
		}
		n, err := b.body.Read(p)
		b.remaining -= int64(n)
		return n, err
	}
	var extra [1]byte
	for {
		n, err := b.body.Read(extra[:])
		if n > 0 {
			return 0, errors.Join(errModernBodyLimit, b.Close())
		}
		if err != nil {
			return 0, err
		}
	}
}

func (b *boundedModernResponseBody) Close() error {
	b.closeOnce.Do(func() {
		b.closeErr = b.body.Close()
	})
	return b.closeErr
}

func normalizeModernRPCErrorResponse(req *http.Request, resp *http.Response) (*http.Response, bool, error) {
	if !modernApplicationJSONContentType(resp.Header.Get("Content-Type")) {
		return resp, resp.StatusCode == http.StatusBadRequest, nil
	}
	requestID, ok := modernRequestID(req)
	if !ok {
		return resp, false, nil
	}
	body, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil {
		return nil, false, errors.Join(readErr, closeErr)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))

	if !validModernRPCErrorEnvelope(body, requestID) {
		candidate := resp.StatusCode == http.StatusBadRequest && !hasTopLevelJSONMember(body, "result")
		return resp, candidate, nil
	}
	resp.StatusCode = http.StatusOK
	resp.Status = strconv.Itoa(http.StatusOK) + " " + http.StatusText(http.StatusOK)
	resp.Header = resp.Header.Clone()
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	for _, value := range resp.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			resp.Header.Del(strings.TrimSpace(token))
		}
	}
	for _, header := range []string{
		"Connection",
		"Content-Encoding",
		"Content-MD5",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Proxy-Connection",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	} {
		resp.Header.Del(header)
	}
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	resp.TransferEncoding = nil
	resp.Trailer = nil
	resp.Close = false
	resp.Uncompressed = false
	return resp, false, nil
}

func modernRequestID(req *http.Request) (json.RawMessage, bool) {
	if !modernApplicationJSONContentType(req.Header.Get("Content-Type")) {
		return nil, false
	}
	if req.GetBody == nil {
		return nil, false
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, false
	}
	data, readErr := io.ReadAll(io.LimitReader(body, maxModernResponseBodyBytes+1))
	closeErr := body.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) > maxModernResponseBodyBytes {
		return nil, false
	}
	envelope, ok := decodeUniqueModernJSONObject(data)
	if !ok || !modernJSONStringEquals(envelope["jsonrpc"], "2.0") {
		return nil, false
	}
	if _, hasResult := envelope["result"]; hasResult {
		return nil, false
	}
	if _, hasError := envelope["error"]; hasError {
		return nil, false
	}
	method, hasMethod := envelope["method"]
	if !hasMethod || !validModernJSONString(method) {
		return nil, false
	}
	id, hasID := envelope["id"]
	if !hasID || !validModernJSONRPCID(id) {
		return nil, false
	}
	return append(json.RawMessage(nil), bytes.TrimSpace(id)...), true
}

func modernApplicationJSONContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && strings.EqualFold(mediaType, "application/json")
}

func validModernRPCErrorEnvelope(body []byte, requestID json.RawMessage) bool {
	envelope, ok := decodeUniqueModernJSONObject(body)
	if !ok || !modernJSONStringEquals(envelope["jsonrpc"], "2.0") {
		return false
	}
	id, hasID := envelope["id"]
	if !hasID || !validModernJSONRPCID(id) || !bytes.Equal(bytes.TrimSpace(id), requestID) {
		return false
	}
	if _, hasResult := envelope["result"]; hasResult {
		return false
	}
	if _, hasMethod := envelope["method"]; hasMethod {
		return false
	}
	rawError, hasError := envelope["error"]
	if !hasError {
		return false
	}
	errorObject, ok := decodeUniqueModernJSONObject(rawError)
	if !ok {
		return false
	}
	code, hasCode := errorObject["code"]
	if !hasCode || !validModernInt64(code) {
		return false
	}
	message, hasMessage := errorObject["message"]
	return hasMessage && validModernJSONString(message)
}

func decodeUniqueModernJSONObject(data []byte) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return nil, false
	}
	open, ok := token.(json.Delim)
	if !ok || open != '{' {
		return nil, false
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, false
		}
		name, ok := token.(string)
		if !ok {
			return nil, false
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, false
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, false
		}
		fields[name] = value
	}
	token, err = decoder.Token()
	if err != nil {
		return nil, false
	}
	closeDelimiter, ok := token.(json.Delim)
	if !ok || closeDelimiter != '}' {
		return nil, false
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, false
	}
	return fields, true
}

func modernJSONStringEquals(raw json.RawMessage, expected string) bool {
	if !validModernJSONString(raw) {
		return false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return false
	}
	return value == expected
}

func validModernJSONString(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) < 2 || raw[0] != '"' {
		return false
	}
	var value string
	return json.Unmarshal(raw, &value) == nil
}

func validModernJSONRPCID(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	if validModernJSONString(raw) {
		return true
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return false
	}
	if _, ok := value.(json.Number); !ok {
		return false
	}
	var trailing json.RawMessage
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

func validModernInt64(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return false
	}
	_, err := strconv.ParseInt(string(raw), 10, 64)
	return err == nil
}

func (m *modernUpstream) SupportsResources() bool {
	return true
}

func (m *modernUpstream) SupportsPrompts() bool {
	return true
}

func (m *modernUpstream) ListTools(ctx context.Context) ([]appmcp.Tool, error) {
	return paginateModern(ctx, "tools/list", func(ctx context.Context, cursor string) ([]appmcp.Tool, string, error) {
		raw, err := m.call(ctx, "tools/list", &sdk.ListToolsParams{Meta: m.metadata(), Cursor: cursor})
		if err != nil {
			return nil, "", err
		}
		var result sdk.ListToolsResult
		if err := json.Unmarshal(raw, &result); err != nil {
			return nil, "", m.unreachable(ctx, "decode tools/list result", err)
		}
		items, err := mapItems[appmcp.Tool]("tools/list", result.Tools)
		return items, result.NextCursor, err
	})
}

func (m *modernUpstream) CallTool(ctx context.Context, call appmcp.ToolCall) (json.RawMessage, error) {
	params := &sdk.CallToolParams{Meta: m.metadataForToolCall(ctx, call), Name: call.Name}
	if len(call.Arguments) > 0 {
		params.Arguments = call.Arguments
	}
	if len(call.InputResponses) > 0 {
		var responses sdk.InputResponseMap
		if err := json.Unmarshal(call.InputResponses, &responses); err != nil {
			return nil, fmt.Errorf("%w: %w", appmcp.ErrInvalidContinuation, err)
		}
		params.InputResponses = responses
	}
	params.RequestState = call.RequestState
	return m.call(ctx, "tools/call", params)
}

func (m *modernUpstream) ListResources(ctx context.Context) ([]appmcp.Resource, error) {
	return paginateModern(ctx, "resources/list", func(ctx context.Context, cursor string) ([]appmcp.Resource, string, error) {
		raw, err := m.call(ctx, "resources/list", &sdk.ListResourcesParams{Meta: m.metadata(), Cursor: cursor})
		if err != nil {
			return nil, "", err
		}
		var result sdk.ListResourcesResult
		if err := json.Unmarshal(raw, &result); err != nil {
			return nil, "", m.unreachable(ctx, "decode resources/list result", err)
		}
		items, err := mapItems[appmcp.Resource]("resources/list", result.Resources)
		return items, result.NextCursor, err
	})
}

func (m *modernUpstream) ListResourceTemplates(ctx context.Context) ([]appmcp.ResourceTemplate, error) {
	return paginateModern(
		ctx,
		"resources/templates/list",
		func(ctx context.Context, cursor string) ([]appmcp.ResourceTemplate, string, error) {
			raw, err := m.call(
				ctx,
				"resources/templates/list",
				&sdk.ListResourceTemplatesParams{Meta: m.metadata(), Cursor: cursor},
			)
			if err != nil {
				return nil, "", err
			}
			var result sdk.ListResourceTemplatesResult
			if err := json.Unmarshal(raw, &result); err != nil {
				return nil, "", m.unreachable(ctx, "decode resources/templates/list result", err)
			}
			items, err := mapItems[appmcp.ResourceTemplate](
				"resources/templates/list",
				result.ResourceTemplates,
			)
			return items, result.NextCursor, err
		},
	)
}

func (m *modernUpstream) ReadResource(ctx context.Context, uri string) (json.RawMessage, error) {
	return m.call(ctx, "resources/read", &sdk.ReadResourceParams{
		Meta: m.metadata(),
		URI:  uri,
	})
}

func (m *modernUpstream) ListPrompts(ctx context.Context) ([]appmcp.Prompt, error) {
	return paginateModern(ctx, "prompts/list", func(ctx context.Context, cursor string) ([]appmcp.Prompt, string, error) {
		raw, err := m.call(ctx, "prompts/list", &sdk.ListPromptsParams{Meta: m.metadata(), Cursor: cursor})
		if err != nil {
			return nil, "", err
		}
		var result sdk.ListPromptsResult
		if err := json.Unmarshal(raw, &result); err != nil {
			return nil, "", m.unreachable(ctx, "decode prompts/list result", err)
		}
		items, err := mapItems[appmcp.Prompt]("prompts/list", result.Prompts)
		return items, result.NextCursor, err
	})
}

func (m *modernUpstream) GetPrompt(
	ctx context.Context,
	name string,
	arguments map[string]string,
) (json.RawMessage, error) {
	return m.call(ctx, "prompts/get", &sdk.GetPromptParams{
		Meta:      m.metadata(),
		Name:      name,
		Arguments: arguments,
	})
}

func (m *modernUpstream) Close(context.Context) {}

func (m *modernUpstream) metadata() sdk.Meta {
	return sdk.Meta{
		sdk.MetaKeyProtocolVersion: m.protocolVersion,
		sdk.MetaKeyClientInfo: &sdk.Implementation{
			Name:    clientName,
			Version: m.implementationVersion,
		},
		sdk.MetaKeyClientCapabilities: map[string]any{},
	}
}

// metadataForToolCall forwards the northbound client's allowlisted capabilities
// so the upstream may ask for input. An empty capability object would tell the
// upstream that nothing can be elicited, so it is omitted on continuation calls
// rather than sent as `{}`.
func (m *modernUpstream) metadataForToolCall(ctx context.Context, call appmcp.ToolCall) sdk.Meta {
	meta := m.metadata()
	caps := appmcp.ClientCapabilitiesFromContext(ctx)
	if len(caps) > 0 {
		meta[sdk.MetaKeyClientCapabilities] = caps
		return meta
	}
	if call.RequestState != "" || len(call.InputResponses) > 0 {
		delete(meta, sdk.MetaKeyClientCapabilities)
	}
	return meta
}

func (m *modernUpstream) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	rawParams, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("mcp modern: %s: encode params: %w", method, err)
	}
	id, err := jsonrpc.MakeID(fmt.Sprintf("trustgate-modern-%d", m.nextID.Add(1)))
	if err != nil {
		return nil, fmt.Errorf("mcp modern: %s: create request ID: %w", method, err)
	}
	request := &jsonrpc.Request{ID: id, Method: method, Params: rawParams}
	candidateKey, err := json.Marshal(id.Raw())
	if err != nil {
		return nil, fmt.Errorf("mcp modern: %s: encode request ID: %w", method, err)
	}
	defer m.eraCandidates.Delete(string(candidateKey))
	transport := &sdk.StreamableClientTransport{
		Endpoint:             m.target.URL,
		HTTPClient:           m.httpClient,
		MaxRetries:           -1,
		DisableStandaloneSSE: true,
	}
	conn, err := transport.Connect(ctx)
	if err != nil {
		return nil, m.unreachable(ctx, "connect modern transport", err)
	}
	result, callErr := m.exchange(ctx, conn, request, id)
	closeErr := conn.Close()
	if callErr != nil {
		if _, candidate := m.eraCandidates.Load(string(candidateKey)); candidate {
			callErr = newEraCandidateError(eraLegacy)
		}
		if closeErr != nil {
			return nil, errors.Join(callErr, m.unreachable(ctx, "close modern transport", closeErr))
		}
		return nil, callErr
	}
	if closeErr != nil {
		return nil, m.unreachable(ctx, "close modern transport", closeErr)
	}
	return result, nil
}

func (m *modernUpstream) exchange(
	ctx context.Context,
	conn sdk.Connection,
	request *jsonrpc.Request,
	id jsonrpc.ID,
) (json.RawMessage, error) {
	if err := conn.Write(ctx, request); err != nil {
		return nil, m.unreachable(ctx, "write modern request", err)
	}
	for messageNumber := 0; messageNumber < maxModernResponseMessages; messageNumber++ {
		message, err := conn.Read(ctx)
		if err != nil {
			return nil, m.unreachable(ctx, "read modern response", err)
		}
		switch message := message.(type) {
		case *jsonrpc.Request:
			if message.IsCall() {
				return nil, m.unreachable(ctx, "read modern response", errModernMessageType)
			}
		case *jsonrpc.Response:
			if message.ID.Raw() != id.Raw() {
				return nil, m.unreachable(ctx, "read modern response", errModernResponseID)
			}
			if message.Error != nil {
				return nil, mapModernRPCError(message.Error)
			}
			return append(json.RawMessage(nil), message.Result...), nil
		default:
			return nil, m.unreachable(ctx, "read modern response", errModernMessageType)
		}
	}
	return nil, m.unreachable(ctx, "read modern response", errModernResponseLimit)
}

func (m *modernUpstream) unreachable(ctx context.Context, category string, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return wrapUnreachable(m.origin, category, err)
}

func mapModernRPCError(err error) error {
	mapped := mapRPCError(err)
	var rpcErr *appmcp.RPCError
	if errors.As(mapped, &rpcErr) && rpcErr.Code == jsonrpc.CodeMethodNotFound {
		return errors.Join(appmcp.ErrNotSupported, mapped)
	}
	return mapped
}

func paginateModern[T any](
	ctx context.Context,
	method string,
	page func(context.Context, string) ([]T, string, error),
) ([]T, error) {
	var items []T
	cursor := ""
	seen := make(map[string]struct{})
	for pageNumber := 0; pageNumber < maxModernPages; pageNumber++ {
		pageItems, nextCursor, err := page(ctx, cursor)
		if err != nil {
			return nil, err
		}
		if len(pageItems) > maxModernItems-len(items) {
			return nil, fmt.Errorf("%w: %s", errModernItemLimit, method)
		}
		items = append(items, pageItems...)
		if nextCursor == "" {
			return items, nil
		}
		if _, exists := seen[nextCursor]; exists {
			return nil, fmt.Errorf("%w: %s", errModernCursorCycle, method)
		}
		seen[nextCursor] = struct{}{}
		cursor = nextCursor
	}
	return nil, fmt.Errorf("%w: %s", errModernPageLimit, method)
}
