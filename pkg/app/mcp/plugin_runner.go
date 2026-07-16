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
// (unknown/empty tier). Aligns with HTTP 503 on the proxy path.
const CodeUnavailable int64 = -32005

const trustGuardRateLimitedType = "trustguard_rate_limited"

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

// NewPluginRunner accepts the shared executor port; a nil executor makes every
// method a no-op (plugin-free parity with today's MCP path).
func NewPluginRunner(executor appplugins.Executor, logger *slog.Logger) *PluginRunner {
	return &PluginRunner{executor: executor, logger: logger}
}

type mcpToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// PreRequest runs StagePreRequest over the tools/call params. It returns nil to
// allow the call; a non-nil *RPCError means a policy blocked it (caller skips the
// upstream dial and writes the error). Per RUN-832 the call fails open on any
// non-block error (guard unavailable, decode failure): it is logged and nil is
// returned so the tools/call proceeds.
func (r *PluginRunner) PreRequest(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	name string,
	arguments json.RawMessage,
) error {
	if r.executor == nil || rc == nil || rc.Consumer == nil {
		return nil
	}
	reqCtx, err := r.buildRequestContext(ctx, rc, name, arguments)
	if err != nil {
		r.logFailOpen(rc, policy.StagePreRequest, directionInput, err)
		return nil
	}
	outcome, err := r.executor.RunStage(ctx, appplugins.StageInput{
		Stage:    policy.StagePreRequest,
		Policies: rc.Policies,
		Plan:     rc.PolicyPlan,
		Request:  reqCtx,
	})
	if err != nil {
		if pe, ok := appplugins.AsPluginError(err); ok {
			return blockToRPCError(pe)
		}
		r.logFailOpen(rc, policy.StagePreRequest, directionInput, err)
		return nil
	}
	if outcome != nil && outcome.ShortCircuit {
		return blockToRPCError(&appplugins.PluginError{
			StatusCode: outcome.StatusCode,
			Message:    "request blocked by policy",
			Body:       outcome.Body,
		})
	}
	return nil
}

// PreResponse runs StagePreResponse over the tool result. It returns nil to keep
// the original result; a non-nil *RPCError means the response is blocked (caller
// discards the result and writes the error). Per RUN-832 the call fails open on
// any non-block error in this direction too: it is logged and the original
// result is kept.
func (r *PluginRunner) PreResponse(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	name string,
	arguments json.RawMessage,
	result json.RawMessage,
) error {
	if r.executor == nil || rc == nil || rc.Consumer == nil {
		return nil
	}
	reqCtx, err := r.buildRequestContext(ctx, rc, name, arguments)
	if err != nil {
		r.logFailOpen(rc, policy.StagePreResponse, directionOutput, err)
		return nil
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
			return blockToRPCError(pe)
		}
		r.logFailOpen(rc, policy.StagePreResponse, directionOutput, err)
		return nil
	}
	if outcome != nil && outcome.ShortCircuit {
		return blockToRPCError(&appplugins.PluginError{
			StatusCode: outcome.StatusCode,
			Message:    "response blocked by policy",
			Body:       outcome.Body,
		})
	}
	return nil
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
	return &RPCError{
		Code:        code,
		Message:     msg,
		Data:        body,
		HTTPHeaders: headers,
	}
}
