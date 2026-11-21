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
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"net/http"
	"strconv"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

// PluginRunner runs a consumer's policies over the normalised parts of an A2A
// call. A block answers -32090, a 429 answers -32091, and any other failure
// fails open. A policy that masks the parts has its masks written into the
// call or the answer (see mask.go); a mask the gateway cannot write blocks
// (-32090, mask_unsupported).
type PluginRunner struct {
	executor appplugins.Executor
	logger   *slog.Logger
}

// NewPluginRunner builds the runner over the shared executor.
func NewPluginRunner(executor appplugins.Executor, logger *slog.Logger) *PluginRunner {
	return &PluginRunner{executor: executor, logger: logger}
}

// PreRequest runs pre_request over the parts of the call. The masks a policy
// writes are written into the call's body, params and parts before anything
// is sent.
func (r *PluginRunner) PreRequest(ctx context.Context, x *Exchange) *RPCError {
	rewritten, rpcErr := r.run(ctx, x, policy.StagePreRequest, nil)
	if rpcErr != nil || rewritten == nil {
		return rpcErr
	}
	eds, err := edits(x.content.Parts, x.content.Paths, rewritten)
	if err != nil {
		return PolicyBlocked(ReasonMaskUnsupported, "")
	}
	if len(eds) == 0 {
		return nil
	}
	body, err := apply(x.call.Body, eds)
	if err != nil {
		return PolicyBlocked(ReasonMaskUnsupported, "")
	}
	var params struct {
		Params json.RawMessage `json:"params"`
	}
	if json.Unmarshal(body, &params) != nil {
		return PolicyBlocked(ReasonMaskUnsupported, "")
	}
	x.call.Body = body
	x.call.Request.Params = params.Params
	var masked appplugins.A2ABody
	_ = json.Unmarshal(rewritten, &masked)
	for i := range x.content.Parts {
		x.content.Parts[i].Text, x.content.Parts[i].Data = masked.Parts[i].Text, masked.Parts[i].Data
	}
	return nil
}

// PreResponse runs pre_response over the parts of the agent's answer, read
// from result as content. It returns result with the masks a policy wrote,
// or result as it is.
func (r *PluginRunner) PreResponse(ctx context.Context, x *Exchange, content Content, result json.RawMessage) (json.RawMessage, *RPCError) {
	rewritten, rpcErr := r.run(ctx, x, policy.StagePreResponse, content.Parts)
	if rpcErr != nil || rewritten == nil {
		return result, rpcErr
	}
	eds, err := edits(content.Parts, content.Paths, rewritten)
	if err != nil {
		return nil, PolicyBlocked(ReasonMaskUnsupported, "")
	}
	if len(eds) == 0 {
		return result, nil
	}
	out, err := apply(result, eds)
	if err != nil {
		return nil, PolicyBlocked(ReasonMaskUnsupported, "")
	}
	return out, nil
}

// run runs a stage over the parts. It returns the normalised body a policy
// rewrote them into, nil when none did: the request body a policy replaced at
// pre_request, or the body of a 2xx short-circuit at pre_response, which is
// how a policy rewrites an answer.
func (r *PluginRunner) run(ctx context.Context, x *Exchange, stage policy.Stage, parts []Part) ([]byte, *RPCError) {
	rc := x.call.Consumer
	body, err := json.Marshal(appplugins.A2ABody{Method: x.call.Request.Method, Agent: x.call.Agent.Name, Parts: nonNil(x.content.Parts)})
	if err != nil {
		r.logFailOpen(ctx, x, stage, err)
		return nil, nil
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
			// The A2A context is the conversation, so a guard groups its turns.
			SessionID: x.content.ContextID,
			Headers:   headers,
			Body:      body,
			A2A:       true,
			A2AMethod: x.call.Request.Method,
			A2ATaskID: x.content.TaskID,
			A2ABody:   x.call.Body,
		},
	}
	in.Request.SetCaller(appconsumer.CallerFromContext(ctx))
	if stage == policy.StagePreResponse {
		out, err := json.Marshal(appplugins.A2ABody{Parts: nonNil(parts)})
		if err != nil {
			r.logFailOpen(ctx, x, stage, err)
			return nil, nil
		}
		in.Response = &infracontext.ResponseContext{GatewayID: in.Request.GatewayID, RegistryID: in.Request.RegistryID, Body: out}
	}
	outcome, err := r.executor.RunStage(ctx, in)
	if err != nil {
		if pe, ok := appplugins.AsPluginError(err); ok {
			return nil, blocked(pe)
		}
		r.logFailOpen(ctx, x, stage, err)
		return nil, nil
	}
	if stage == policy.StagePreResponse {
		if outcome == nil || !outcome.ShortCircuit {
			return nil, nil
		}
		if outcome.StatusCode >= 200 && outcome.StatusCode <= 299 && len(outcome.Body) > 0 {
			return outcome.Body, nil
		}
		return nil, blocked(&appplugins.PluginError{StatusCode: outcome.StatusCode, Headers: outcome.Headers})
	}
	if outcome != nil && outcome.ShortCircuit {
		// A request short-circuit (an answer in place of the agent's) has no
		// A2A form, so it stops the call.
		return nil, blocked(&appplugins.PluginError{StatusCode: outcome.StatusCode, Headers: outcome.Headers})
	}
	if !bytes.Equal(in.Request.Body, body) {
		return in.Request.Body, nil
	}
	return nil, nil
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
