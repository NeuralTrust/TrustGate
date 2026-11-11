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

package a2a

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const (
	upstreamTimeout  = 300 * time.Second
	maxResponseBytes = 8 << 20
)

// Forwarder sends A2A calls to agents through the gateway's checks: the
// method gate, the policies and the registry's credential.
type Forwarder struct {
	upstream    Upstream
	runner      *PluginRunner
	credentials *Credentials
	logger      *slog.Logger
}

// NewForwarder builds the agent plane's forwarder.
func NewForwarder(upstream Upstream, runner *PluginRunner, credentials *Credentials, logger *slog.Logger) *Forwarder {
	return &Forwarder{upstream: upstream, runner: runner, credentials: credentials, logger: logger}
}

// Call is a JSON-RPC request to an agent, as the caller sent it.
type Call struct {
	Consumer  *appconsumer.RoutableConsumer
	Agent     *registrydomain.Registry
	Principal *identity.Principal
	Request   *Request
	Body      []byte
	Header    http.Header
}

// Exchange is a call that passed the gateway's checks, ready to be sent.
type Exchange struct {
	f       *Forwarder
	call    *Call
	version Version
	kind    Kind
	content Content
	header  http.Header
}

// Prepare checks a call before anything reaches the agent: the method of the
// pinned version and the registry's allowed methods, streaming on the card,
// the policies on the request, and the credential.
func (f *Forwarder) Prepare(ctx context.Context, call *Call) (*Exchange, *RPCError) {
	target := call.Agent.A2ATarget
	v := Version(target.ProtocolVersion)
	kind, ok := MethodKind(v, call.Request.Method)
	if !ok {
		return nil, MethodNotFound()
	}
	if refusal := kind.Refusal(v); refusal != nil {
		return nil, refusal
	}
	if len(target.AllowedMethods) > 0 && !slices.Contains(target.AllowedMethods, call.Request.Method) {
		return nil, MethodNotFound()
	}
	if kind.Streams() && !Streaming(target.Card) {
		return nil, UnsupportedOperation(v)
	}
	content, err := RequestContent(v, kind, call.Request.Params)
	if err != nil {
		rpcErr, _ := err.(*RPCError)
		return nil, rpcErr
	}
	x := &Exchange{f: f, call: call, version: v, kind: kind, content: content}
	if blocked := f.runner.PreRequest(ctx, x); blocked != nil {
		return nil, blocked
	}
	credential, _, rpcErr := f.credentials.For(ctx, call.Consumer, call.Agent, call.Principal)
	if rpcErr != nil {
		return nil, rpcErr
	}
	x.header = x.upstreamHeader(ctx, credential)
	return x, nil
}

// Streams reports whether the agent answers the call with an event stream.
func (x *Exchange) Streams() bool {
	return x.kind.Streams()
}

// Send sends a buffered call and returns the agent's result, after the
// policies ran on its parts. An error the agent answered comes back as the
// *RPCError.
func (x *Exchange) Send(ctx context.Context) (json.RawMessage, *RPCError) {
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	res, err := x.f.upstream.Post(ctx, x.call.Agent.A2ATarget.Endpoint(), x.header, x.call.Body)
	if err != nil {
		return nil, upstreamFailure(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil {
		return nil, upstreamFailure(err)
	}
	if len(body) > maxResponseBytes {
		return nil, GatewayFailure(ReasonResponseTooLarge)
	}
	result, rpcErr := decodeResponse(body, res.StatusCode)
	if rpcErr != nil {
		return nil, rpcErr
	}
	content, err := ResultContent(x.version, result)
	if err != nil {
		rpcErr, _ := err.(*RPCError)
		return nil, rpcErr
	}
	if x.kind != KindCancel && len(content.Parts) > 0 {
		if blocked := x.f.runner.PreResponse(ctx, x, content.Parts); blocked != nil {
			return nil, blocked
		}
	}
	return result, nil
}

func (x *Exchange) upstreamHeader(ctx context.Context, credential http.Header) http.Header {
	h := http.Header{}
	for name, value := range x.call.Agent.A2ATarget.Headers {
		h.Set(name, value)
	}
	for name, values := range credential {
		h[name] = values
	}
	h.Set("Content-Type", "application/json")
	if x.kind.Streams() {
		h.Set("Accept", "text/event-stream")
	} else {
		h.Set("Accept", "application/json")
	}
	extensions := "X-A2A-Extensions"
	if x.version == Version10 {
		h.Set("A2A-Version", string(Version10))
		extensions = "A2A-Extensions"
	}
	for _, value := range x.call.Header.Values(extensions) {
		h.Add(extensions, value)
	}
	if rt := trace.FromContext(ctx); rt != nil {
		h.Set("X-AG-Trace-Id", rt.TraceID())
	}
	return h
}

// decodeResponse reads a JSON-RPC response: its result, or the error the
// agent answered. A body that is not one answers -32092.
func decodeResponse(body []byte, status int) (json.RawMessage, *RPCError) {
	o, ok := decodeObject(body)
	if ok {
		if o.has("error") {
			var rpcErr RPCError
			if json.Unmarshal(o["error"], &rpcErr) == nil {
				return nil, &rpcErr
			}
		} else if o.has("result") {
			return o["result"], nil
		}
	}
	if status < 200 || status > 299 {
		return nil, GatewayFailure(ReasonUpstreamError)
	}
	return nil, GatewayFailure(ReasonInvalidUpstreamResponse)
}

func upstreamFailure(err error) *RPCError {
	if errors.Is(err, context.DeadlineExceeded) {
		return GatewayFailure(ReasonUpstreamTimeout)
	}
	return GatewayFailure(ReasonUpstreamUnreachable)
}

// Response is the JSON-RPC response with the caller's id that carries result,
// or rpcErr when it is not nil.
func Response(id json.RawMessage, result json.RawMessage, rpcErr *RPCError) []byte {
	resp := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result,omitempty"`
		Error   *RPCError       `json:"error,omitempty"`
	}{JSONRPC: "2.0", ID: id, Result: result, Error: rpcErr}
	out, _ := json.Marshal(resp)
	return out
}
