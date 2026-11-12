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
	"log/slog"
	"maps"
	"net/http"
	"strconv"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

// PluginRunner runs a consumer's policies over the normalised parts of an A2A
// call. A block answers -32090, a 429 answers -32091, and any other failure
// fails open.
type PluginRunner struct {
	executor appplugins.Executor
	logger   *slog.Logger
}

// NewPluginRunner builds the runner over the shared executor.
func NewPluginRunner(executor appplugins.Executor, logger *slog.Logger) *PluginRunner {
	return &PluginRunner{executor: executor, logger: logger}
}

type normalisedBody struct {
	Method string `json:"method,omitempty"`
	Agent  string `json:"agent,omitempty"`
	Parts  []Part `json:"parts"`
}

// PreRequest runs pre_request over the parts of the call.
func (r *PluginRunner) PreRequest(ctx context.Context, x *Exchange) *RPCError {
	return r.run(ctx, x, policy.StagePreRequest, nil)
}

// PreResponse runs pre_response over parts of the agent's answer.
func (r *PluginRunner) PreResponse(ctx context.Context, x *Exchange, parts []Part) *RPCError {
	return r.run(ctx, x, policy.StagePreResponse, parts)
}

func (r *PluginRunner) run(ctx context.Context, x *Exchange, stage policy.Stage, parts []Part) *RPCError {
	rc := x.call.Consumer
	body, err := json.Marshal(normalisedBody{Method: x.call.Request.Method, Agent: x.call.Agent.Name, Parts: nonNil(x.content.Parts)})
	if err != nil {
		r.logFailOpen(ctx, x, stage, err)
		return nil
	}
	headers := maps.Clone(x.call.Header)
	if headers == nil {
		headers = http.Header{}
	}
	headers.Set("Content-Length", strconv.Itoa(len(x.call.Body)))
	in := appplugins.StageInput{
		Stage:    stage,
		Policies: rc.Policies,
		Plan:     rc.PolicyPlan,
		Request: &infracontext.RequestContext{
			GatewayID:    rc.Consumer.GatewayID.String(),
			ConsumerID:   rc.Consumer.ID.String(),
			ConsumerName: rc.Consumer.Name,
			ConsumerType: string(rc.Consumer.Type),
			RegistryID:   x.call.Agent.ID.String(),
			Headers:      headers,
			Body:         body,
			A2A:          true,
			A2AMethod:    x.call.Request.Method,
			A2ATaskID:    x.content.TaskID,
		},
	}
	if stage == policy.StagePreResponse {
		out, err := json.Marshal(normalisedBody{Parts: nonNil(parts)})
		if err != nil {
			r.logFailOpen(ctx, x, stage, err)
			return nil
		}
		in.Response = &infracontext.ResponseContext{GatewayID: in.Request.GatewayID, RegistryID: in.Request.RegistryID, Body: out}
	}
	outcome, err := r.executor.RunStage(ctx, in)
	if err != nil {
		if pe, ok := appplugins.AsPluginError(err); ok {
			return blocked(pe)
		}
		r.logFailOpen(ctx, x, stage, err)
		return nil
	}
	if outcome != nil && outcome.ShortCircuit {
		// The gateway cannot rewrite A2A parts, so a short-circuit, even one
		// carrying a replacement, stops the call.
		return blocked(&appplugins.PluginError{StatusCode: outcome.StatusCode, Headers: outcome.Headers})
	}
	return nil
}

func blocked(pe *appplugins.PluginError) *RPCError {
	switch {
	case pe.StatusCode == http.StatusTooManyRequests:
		retryAfter, _ := strconv.Atoi(http.Header(pe.Headers).Get("Retry-After"))
		return RateLimited(retryAfter)
	case pe.Type == appplugins.TypeMaskUnsupported:
		return PolicyBlocked(ReasonMaskUnsupported, pe.Plugin)
	default:
		return PolicyBlocked(ReasonPolicyBlocked, pe.Plugin)
	}
}

func (r *PluginRunner) logFailOpen(ctx context.Context, x *Exchange, stage policy.Stage, err error) {
	r.logger.WarnContext(ctx, "a2a plugin stage failed, failing open",
		slog.String("stage", string(stage)),
		slog.String("gateway_id", x.call.Consumer.Consumer.GatewayID.String()),
		slog.String("registry_id", x.call.Agent.ID.String()),
		slog.String("error", err.Error()))
}

func nonNil(parts []Part) []Part {
	if parts == nil {
		return []Part{}
	}
	return parts
}
