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

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

// codePolicyBlocked is a server-defined JSON-RPC error code (in the reserved
// -32000..-32099 range) used when the plugin chain blocks a tools/call;
// -32002 and -32003 are already used elsewhere in the MCP handler.
const codePolicyBlocked int64 = -32001

// CodeRateLimited is returned for gateway plan throttle (rpc_dispatcher) and for
// TrustGuard evaluate 429 (plugin Type trustguard_rate_limited). Policy plugins
// that return HTTP 429 (e.g. per_tool_rate_limiter) keep codePolicyBlocked (-32001).
const CodeRateLimited int64 = -32004

// CodeUnavailable is returned when gateway plan entitlements cannot be resolved
// (unknown tier) or TrustGuard evaluate returns 503. Aligns with HTTP 503 on the proxy path.
const CodeUnavailable int64 = -32005

const trustGuardRateLimitedType = "trustguard_rate_limited"
const trustGuardUnavailableType = "trustguard_unavailable"

const (
	directionInput  = "input"
	directionOutput = "output"
)

// PluginRunner runs the resolved plugin chain on the native MCP tools/call
// path, mirroring pkg/app/proxy for the LLM path. It is a thin adapter over the
// shared plugins.Executor: it builds stage contexts from JSON-RPC values and
// maps a plugin block to a JSON-RPC error.
type PluginRunner struct {
	executor appplugins.Executor
	logger   *slog.Logger
}

// IsPolicyBlockedCode reports whether a JSON-RPC error is a policy denial.
func IsPolicyBlockedCode(code int64) bool { return code == codePolicyBlocked }

// NewPluginRunner accepts the shared executor port; a nil executor makes every
// method a no-op (plugin-free parity with today's MCP path).
func NewPluginRunner(executor appplugins.Executor, logger *slog.Logger) *PluginRunner {
	return &PluginRunner{executor: executor, logger: logger}
}

type mcpToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// StageResult is what a plugin stage decided for a tools/call. A plugin may
// rewrite the payload rather than block it — TrustGuard's data-masking does
// exactly that — so the caller has to carry the rewritten value forward instead
// of reusing the one it sent in.
type StageResult struct {
	// Arguments is the effective tool input after the request stage. Empty when
	// no plugin rewrote it.
	Arguments json.RawMessage
	// Result is a payload that stands in for the tool's output: the masked
	// result from the response stage, or a reply a plugin produced itself in the
	// request stage instead of letting the call reach the upstream.
	Result json.RawMessage
}

// replacesPayload reports whether a short-circuit outcome is a plugin supplying
// a payload rather than denying the call. A denial arrives as a PluginError; a
// 2xx short-circuit is a rewrite, which is how the LLM path reads it too — it
// forwards the outcome's status and body as the response.
func replacesPayload(outcome *appplugins.StageOutcome) bool {
	if outcome == nil || !outcome.ShortCircuit {
		return false
	}
	return outcome.StatusCode == 0 || (outcome.StatusCode >= 200 && outcome.StatusCode < 300)
}

// PreRequest runs StagePreRequest over the tools/call params. The returned
// StageResult carries the effective tool input — a plugin may have rewritten it
// — or a payload a plugin produced in place of calling the upstream at all. A
// non-nil error is an *RPCError: a policy denied the call and the caller skips
// the upstream dial. Per RUN-832 the call fails open on any non-block error
// (guard unavailable, decode failure): it is logged and the call proceeds.
func (r *PluginRunner) PreRequest(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	name string,
	arguments json.RawMessage,
) (*StageResult, error) {
	if r.executor == nil || rc == nil || rc.Consumer == nil {
		return nil, nil
	}
	reqCtx, err := r.buildRequestContext(ctx, rc, name, arguments)
	if err != nil {
		r.logFailOpen(rc, policy.StagePreRequest, directionInput, err)
		return nil, nil
	}
	outcome, err := r.executor.RunStage(ctx, appplugins.StageInput{
		Stage:    policy.StagePreRequest,
		Policies: rc.Policies,
		Plan:     rc.PolicyPlan,
		Request:  reqCtx,
	})
	if err != nil {
		if pe, ok := appplugins.AsPluginError(err); ok {
			return nil, blockToRPCError(pe)
		}
		r.logFailOpen(rc, policy.StagePreRequest, directionInput, err)
		return nil, nil
	}
	if outcome != nil && outcome.ShortCircuit {
		if replacesPayload(outcome) {
			// A plugin answered the call itself instead of denying it.
			return &StageResult{Result: outcome.Body}, nil
		}
		return nil, blockToRPCError(&appplugins.PluginError{
			StatusCode: outcome.StatusCode,
			Message:    "request blocked by policy",
			Body:       outcome.Body,
		})
	}
	// A body writer (TrustGuard data-masking) rewrites the request context in
	// place. Read the arguments back out so the upstream receives the masked
	// payload; forwarding the originals would leak exactly what the plugin was
	// asked to redact.
	return &StageResult{Arguments: r.rewrittenArguments(rc, name, arguments, reqCtx.Body)}, nil
}

// rewrittenArguments extracts the tool arguments a plugin left in the request
// body, or nil when nothing usable changed. The tool name is deliberately not
// honoured: routing is the gateway's decision, not a body writer's.
func (r *PluginRunner) rewrittenArguments(
	rc *appconsumer.RoutableConsumer,
	name string,
	original json.RawMessage,
	body []byte,
) json.RawMessage {
	if len(body) == 0 {
		return nil
	}
	var params mcpToolCallParams
	if err := json.Unmarshal(body, &params); err != nil {
		r.logFailOpen(rc, policy.StagePreRequest, directionInput,
			fmt.Errorf("mcp: plugin left an unparseable tools/call body: %w", err))
		return nil
	}
	if params.Name != name && r.logger != nil {
		r.logger.Warn("mcp plugin rewrote the tool name; ignoring the change",
			slog.String("tool", name), slog.String("rewritten", params.Name))
	}
	if bytes.Equal(params.Arguments, original) {
		return nil
	}
	return params.Arguments
}

// PreResponse runs StagePreResponse over the tool result. A StageResult with a
// Result replaces the tool's output (TrustGuard data-masking); nil keeps the
// original. A non-nil error is an *RPCError: the response was blocked and the
// caller discards the result. Per RUN-832 the call fails open on any non-block
// error in this direction too: it is logged and the original result is kept.
func (r *PluginRunner) PreResponse(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	name string,
	arguments json.RawMessage,
	result json.RawMessage,
) (*StageResult, error) {
	if r.executor == nil || rc == nil || rc.Consumer == nil {
		return nil, nil
	}
	reqCtx, err := r.buildRequestContext(ctx, rc, name, arguments)
	if err != nil {
		r.logFailOpen(rc, policy.StagePreResponse, directionOutput, err)
		return nil, nil
	}
	respCtx := &infracontext.ResponseContext{
		GatewayID: rc.Consumer.GatewayID.String(),
		Body:      result,
		Streaming: false,
	}
	outcome, err := r.executor.RunStage(ctx, appplugins.StageInput{
		Stage:    policy.StagePreResponse,
		Policies: rc.Policies,
		Plan:     rc.PolicyPlan,
		Request:  reqCtx,
		Response: respCtx,
	})
	if err != nil {
		if pe, ok := appplugins.AsPluginError(err); ok {
			return nil, blockToRPCError(pe)
		}
		r.logFailOpen(rc, policy.StagePreResponse, directionOutput, err)
		return nil, nil
	}
	if outcome != nil && outcome.ShortCircuit {
		// TrustGuard signals a masked result the same way it signals a canned
		// reply: a short-circuit carrying a body. A 2xx one is a rewrite, so the
		// masked payload becomes the tool's output — treating it as a denial
		// failed the call and handed the agent nothing.
		if replacesPayload(outcome) {
			return &StageResult{Result: outcome.Body}, nil
		}
		return nil, blockToRPCError(&appplugins.PluginError{
			StatusCode: outcome.StatusCode,
			Message:    "response blocked by policy",
			Body:       outcome.Body,
		})
	}
	return nil, nil
}

// logFailOpen records a guard/plugin failure that the runner deliberately does
// not surface. RUN-832 requires a tools/call to proceed on guard errors in both
// directions; only ids and outcome are logged, never tool payloads.
func (r *PluginRunner) logFailOpen(rc *appconsumer.RoutableConsumer, stage policy.Stage, direction string, err error) {
	if r.logger == nil {
		return
	}
	r.logger.Warn("mcp plugin stage failed, failing open",
		slog.String("stage", string(stage)),
		slog.String("direction", direction),
		slog.String("outcome", "failed_open"),
		slog.String("gateway_id", rc.Consumer.GatewayID.String()),
		slog.String("error", err.Error()),
	)
}

func (r *PluginRunner) buildRequestContext(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	name string,
	arguments json.RawMessage,
) (*infracontext.RequestContext, error) {
	body, err := json.Marshal(mcpToolCallParams{Name: name, Arguments: arguments})
	if err != nil {
		return nil, fmt.Errorf("mcp: marshal tools/call params: %w", err)
	}
	return &infracontext.RequestContext{
		GatewayID:      rc.Consumer.GatewayID.String(),
		ConsumerID:     rc.Consumer.ID.String(),
		ConsumerType:   string(rc.Consumer.Type),
		SessionID:      "",
		Provider:       "",
		SourceFormat:   "",
		RequestedModel: "",
		MCP:            true,
		Body:           body,
	}, nil
}

func blockToRPCError(pe *appplugins.PluginError) *RPCError {
	code := codePolicyBlocked
	// Only TrustGuard plan-limit 429 maps to -32004; policy rate limiters stay -32001.
	if pe != nil && pe.StatusCode == http.StatusTooManyRequests && pe.Type == trustGuardRateLimitedType {
		code = CodeRateLimited
	}
	if pe != nil && pe.StatusCode == http.StatusServiceUnavailable && pe.Type == trustGuardUnavailableType {
		code = CodeUnavailable
	}
	var headers map[string][]string
	if pe != nil && len(pe.Headers) > 0 {
		headers = pe.Headers
	}
	msg := "request blocked by policy"
	var body json.RawMessage
	if pe != nil {
		if pe.Message != "" {
			msg = pe.Message
		}
		body = pe.Body
	}
	httpStatus := http.StatusForbidden
	if pe != nil && pe.StatusCode != 0 {
		httpStatus = pe.StatusCode
	}
	return &RPCError{
		Code:        code,
		Message:     msg,
		Data:        body,
		HTTPStatus:  httpStatus,
		HTTPHeaders: headers,
	}
}
