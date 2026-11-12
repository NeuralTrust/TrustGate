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
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const maxResponseBytes = 8 << 20

var upstreamTimeout = 300 * time.Second

// Forwarder sends A2A calls to agents through the gateway's checks: the
// method gate, task ownership, the policies and the registry's credential.
type Forwarder struct {
	upstream    Upstream
	runner      *PluginRunner
	credentials *Credentials
	ownership   OwnershipStore
	logger      *slog.Logger
}

// NewForwarder builds the agent plane's forwarder.
func NewForwarder(upstream Upstream, runner *PluginRunner, credentials *Credentials, ownership OwnershipStore, logger *slog.Logger) *Forwarder {
	return &Forwarder{upstream: upstream, runner: runner, credentials: credentials, ownership: ownership, logger: logger}
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
	f        *Forwarder
	call     *Call
	provider provider
	version  Version
	kind     Kind
	content  Content
	owner    Owner
	session  string
	header   http.Header

	span       *trace.Span
	attrs      trace.A2AAttrs
	sentAt     time.Time
	agentError bool
}

// Prepare checks a call before anything reaches the agent: the method of the
// pinned version and the registry's allowed methods, streaming on the card,
// the owner of the task or context it names, the policies on the request,
// and the credential.
func (f *Forwarder) Prepare(ctx context.Context, call *Call) (*Exchange, *RPCError) {
	x := &Exchange{f: f, call: call, provider: providerOf(call.Agent.A2ATarget), version: call.Agent.A2ATarget.ProtocolVersion, owner: ownerOf(call)}
	x.attrs = trace.A2AAttrs{
		Method:          call.Request.Method,
		RegistryID:      call.Agent.ID.String(),
		AgentName:       call.Agent.Name,
		Provider:        string(call.Agent.A2ATarget.Provider),
		ProtocolVersion: string(x.version),
	}
	if rt := trace.FromContext(ctx); rt != nil {
		x.span = rt.StartSpan(trace.SpanA2A, call.Request.Method)
	}
	if rpcErr := x.prepare(ctx); rpcErr != nil {
		x.finish(rpcErr)
		return nil, rpcErr
	}
	return x, nil
}

func (x *Exchange) prepare(ctx context.Context) *RPCError {
	target := x.call.Agent.A2ATarget
	kind, ok := MethodKind(x.version, x.call.Request.Method)
	if !ok {
		return MethodNotFound()
	}
	x.kind = kind
	if refusal := kind.Refusal(x.version); refusal != nil {
		return refusal
	}
	if len(target.AllowedMethods) > 0 && !slices.Contains(target.AllowedMethods, x.call.Request.Method) {
		return MethodNotFound()
	}
	if kind.Streams() && (!Streaming(target.Card) || !x.provider.capabilities().streams) {
		return UnsupportedOperation(x.version)
	}
	content, rpcErr := RequestContent(x.version, kind, x.call.Request.Params)
	if rpcErr != nil {
		return rpcErr
	}
	x.content = content
	x.attrs.TaskID, x.attrs.ContextID = content.TaskID, content.ContextID
	if rpcErr := x.checkOwner(ctx); rpcErr != nil {
		return rpcErr
	}
	if blocked := x.f.runner.PreRequest(ctx, x); blocked != nil {
		return blocked
	}
	credential, sent, rpcErr := x.f.credentials.For(ctx, x.call.Consumer, x.call.Agent, x.call.Principal)
	x.attrs.IdentityMode, x.attrs.IdentitySubjectKind = sent.Mode, sent.SubjectKind
	if rpcErr != nil {
		return rpcErr
	}
	x.header = x.upstreamHeader(ctx, credential)
	return nil
}

// Streams reports whether the agent answers the call with an event stream.
func (x *Exchange) Streams() bool {
	return x.kind.Streams()
}

// Send sends a buffered call and returns the agent's result, after the
// policies ran on its parts. An error the agent answered comes back as the
// *RPCError.
func (x *Exchange) Send(ctx context.Context) (result json.RawMessage, rpcErr *RPCError) {
	defer func() { x.finish(rpcErr) }()
	ctx, cancel := context.WithTimeout(ctx, upstreamTimeout)
	defer cancel()
	for attempt := 0; ; attempt++ {
		result, rpcErr = x.attempt(ctx)
		if rpcErr == nil {
			break
		}
		wait, again := x.provider.retry(rpcErr, attempt)
		if !again {
			return nil, rpcErr
		}
		select {
		case <-ctx.Done():
			return nil, upstreamFailure(ctx.Err())
		case <-time.After(wait):
		}
	}
	content, rpcErr := x.resultContent(result)
	if rpcErr != nil {
		return nil, rpcErr
	}
	if x.kind == KindCancel {
		if result, rpcErr = StripTaskContent(x.version, result); rpcErr != nil {
			return nil, rpcErr
		}
	} else if len(content.Parts) > 0 {
		if blocked := x.f.runner.PreResponse(ctx, x, content.Parts); blocked != nil {
			return nil, blocked
		}
	}
	if rpcErr := x.recordOwner(ctx, content); rpcErr != nil {
		return nil, rpcErr
	}
	return result, nil
}

func (x *Exchange) attempt(ctx context.Context) (json.RawMessage, *RPCError) {
	x.agentError = false
	res, err := x.post(ctx, x.header, x.call.Body)
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
	result, rpcErr, fromAgent := x.provider.decode(x, res, body)
	x.agentError = fromAgent
	return result, rpcErr
}

// post sends body to the agent and records when it went and how the agent
// answered.
func (x *Exchange) post(ctx context.Context, header http.Header, body []byte) (*http.Response, error) {
	x.sentAt = time.Now()
	res, err := x.do(ctx, header, body)
	if err == nil {
		x.attrs.UpstreamStatus = res.StatusCode
	}
	return res, err
}

// do sends a JSON-RPC body to the agent as its provider takes it, signed with
// the registry's cloud credential.
func (x *Exchange) do(ctx context.Context, header http.Header, body []byte) (*http.Response, error) {
	req, err := x.provider.request(ctx, x, x.call.Agent.A2ATarget.Endpoint(), header.Clone(), body)
	if err != nil {
		return nil, err
	}
	if err := x.f.credentials.Sign(ctx, x.call.Agent, req); err != nil {
		x.f.logger.WarnContext(ctx, "a2a cloud credential failed", slog.String("registry_id", x.call.Agent.ID.String()), slog.String("error", err.Error()))
		return nil, errCloudAuth
	}
	return x.f.upstream.Do(req)
}

// decodeRPC reads a JSON-RPC response: its result, or the error the agent
// answered, with fromAgent true. A body that is not one answers -32092.
func decodeRPC(body []byte, status int) (result json.RawMessage, rpcErr *RPCError, fromAgent bool) {
	o, ok := decodeObject(body)
	if ok {
		if o.has("error") {
			var agentErr RPCError
			if json.Unmarshal(o["error"], &agentErr) == nil {
				return nil, &agentErr, true
			}
		} else if o.has("result") {
			return o["result"], nil, false
		}
	}
	if status < 200 || status > 299 {
		return nil, GatewayFailure(ReasonUpstreamError), false
	}
	return nil, GatewayFailure(ReasonInvalidUpstreamResponse), false
}

// resultContent reads a result or an event and records the task it names.
func (x *Exchange) resultContent(result json.RawMessage) (Content, *RPCError) {
	content, rpcErr := ResultContent(x.version, result)
	if rpcErr != nil {
		return Content{}, rpcErr
	}
	if content.TaskID != "" {
		x.attrs.TaskID = content.TaskID
	}
	if content.ContextID != "" {
		x.attrs.ContextID = content.ContextID
	}
	if content.State != "" {
		x.attrs.TaskState = content.State
	}
	return content, nil
}

// Outcomes of an A2A call, as its span records them.
const (
	OutcomeOK              = "ok"
	OutcomeBlocked         = "blocked"
	OutcomeRefused         = "refused"
	OutcomeNotFound        = "not_found"
	OutcomeUpstreamError   = "upstream_error"
	OutcomeUpstreamTimeout = "upstream_timeout"
)

func (x *Exchange) finish(rpcErr *RPCError) {
	if x.span == nil {
		return
	}
	a := &x.attrs
	a.Outcome = OutcomeOK
	if rpcErr != nil {
		var data struct {
			Reason string `json:"reason"`
			Plugin string `json:"plugin"`
		}
		// An agent's error may carry no data or data of another shape; the
		// span then records no reason or plugin.
		_ = json.Unmarshal(rpcErr.Data, &data)
		if data.Reason != "" {
			a.Reason = data.Reason
		}
		a.RPCErrorCode = int(rpcErr.Code)
		switch {
		case x.agentError:
			a.Outcome = OutcomeUpstreamError
		case rpcErr.Code == CodePolicyBlocked:
			a.Outcome, a.BlockedBy = OutcomeBlocked, data.Plugin
		case rpcErr.Code == CodeRateLimited:
			a.Outcome, a.Reason = OutcomeBlocked, "rate_limited"
		case rpcErr.Code == CodeTaskNotFound:
			a.Outcome = OutcomeNotFound
		case rpcErr.Code != CodeGatewayFailure:
			a.Outcome = OutcomeRefused
		case data.Reason == ReasonUpstreamTimeout || data.Reason == ReasonStreamIdle:
			a.Outcome = OutcomeUpstreamTimeout
		case data.Reason != ReasonStreamMaxDuration:
			a.Outcome = OutcomeUpstreamError
		}
		x.span.SetError(rpcErr.Message)
	}
	x.span.SetA2A(*a)
	if x.sentAt.IsZero() {
		x.span.SetLatency(0)
	} else {
		x.span.SetLatency(time.Since(x.sentAt))
	}
	x.span.End()
}

func ownerOf(call *Call) Owner {
	o := Owner{ConsumerID: call.Consumer.Consumer.ID, Subject: consumerdomain.AppSubject(call.Consumer.Consumer.ID)}
	if call.Principal != nil && call.Principal.Subject != "" {
		o.Subject = call.Principal.Subject
	}
	return o
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
	x.provider.header(x, h)
	return h
}

var errCloudAuth = errors.New("a2a: cloud credential failed")

func upstreamFailure(err error) *RPCError {
	var rpcErr *RPCError
	if errors.As(err, &rpcErr) {
		return rpcErr
	}
	if errors.Is(err, errCloudAuth) {
		return GatewayFailure(ReasonCloudAuthFailed)
	}
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
	out, err := json.Marshal(resp)
	if err != nil {
		resp.Result, resp.Error = nil, GatewayFailure(ReasonInvalidUpstreamResponse)
		// The id was read from the caller's valid JSON and the error is the
		// gateway's own, so this second encoding cannot fail.
		out, _ = json.Marshal(resp)
	}
	return out
}
