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

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

type taskRequestParams struct {
	TaskID         string          `json:"taskId"`
	InputResponses json.RawMessage `json:"inputResponses,omitempty"`
}

func (g *RPCGateway) dispatchTask(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	method string,
	params json.RawMessage,
) (any, error) {
	var p taskRequestParams
	if err := json.Unmarshal(params, &p); err != nil || p.TaskID == "" {
		return nil, &InvalidParamsError{Reason: method + " requires params.taskId"}
	}
	if err := requireTasksCapability(ctx); err != nil {
		stampTask(ctx, method, trace.TaskOutcomeCapabilityRequired)
		return nil, err
	}
	// Polling is metered on the consumer's existing MCP bucket: a task must not
	// give a client a second, unmetered budget.
	if err := g.checkRateLimit(ctx, rc); err != nil {
		return nil, err
	}
	ref, err := g.composer.UnwrapTaskHandle(ctx, rc, p.TaskID)
	if err != nil {
		stampTask(ctx, method, trace.TaskOutcomeHandleRejected)
		return nil, appmcp.MapTaskError(err)
	}
	result, err := g.callTask(ctx, rc, method, ref, p)
	if err != nil {
		stampTask(ctx, method, trace.TaskOutcomeHandleRejected)
		return nil, appmcp.MapTaskError(err)
	}
	result, err = g.inspectTerminalTask(ctx, rc, ref, result)
	if err != nil {
		stampTask(ctx, method, trace.TaskOutcomePolicyDenied)
		return nil, err
	}
	stampTask(ctx, method, taskOutcome(result))
	return result, nil
}

func (g *RPCGateway) callTask(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	method string,
	ref appmcp.TaskRef,
	p taskRequestParams,
) (json.RawMessage, error) {
	switch method {
	case appmcp.MethodTasksGet:
		return g.composer.GetTask(ctx, rc, p.TaskID)
	case appmcp.MethodTasksUpdate:
		// The answer a client supplies is tool input, so it takes the request
		// stage under the exposed tool name the handle recovered.
		pre, err := g.plugins.PreRequest(ctx, rc, ref.Exposed, nil, p.InputResponses)
		if err != nil {
			return nil, err
		}
		responses := p.InputResponses
		if pre != nil && pre.InputResponses != nil {
			responses = pre.InputResponses
		}
		return g.composer.UpdateTask(ctx, rc, p.TaskID, responses)
	case appmcp.MethodTasksCancel:
		return g.composer.CancelTask(ctx, rc, p.TaskID)
	default:
		return nil, appmcp.ErrTaskHandleRejected
	}
}

// inspectTerminalTask runs the response stage over the tool output a completed
// task carries. Without it long-running output would reach the client having
// never been scanned, because the tools/call that started the task returned only
// a task envelope.
func (g *RPCGateway) inspectTerminalTask(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	ref appmcp.TaskRef,
	result json.RawMessage,
) (json.RawMessage, error) {
	inner, ok := appmcp.TerminalTaskResult(result)
	if !ok {
		return result, nil
	}
	post, err := g.plugins.PreResponse(ctx, rc, ref.Exposed, nil, inner)
	if err != nil {
		return nil, err
	}
	if post != nil && post.Result != nil {
		return appmcp.ReplaceTaskResult(result, post.Result), nil
	}
	return result, nil
}

// requireTasksCapability refuses tasks/* from a client that never declared the
// extension: it could not have received a handle, and answering would leak that
// the methods exist for someone else.
func requireTasksCapability(ctx context.Context) error {
	if appmcp.DeclaredTasksExtension(appmcp.ClientCapabilitiesFromContext(ctx)) {
		return nil
	}
	return appmcp.TaskCapabilityRequiredRPCError()
}

func stampTask(ctx context.Context, method, outcome string) {
	if span := trace.SpanFromContext(ctx); span != nil {
		span.SetMCPTask(trace.BoundTaskOperation(method), outcome)
	}
}

// taskOutcome maps a mediated task's reported status onto the bounded telemetry
// outcome set.
func taskOutcome(result json.RawMessage) string {
	_, status, _, ok := appmcp.TaskResultFields(result)
	if !ok {
		return trace.TaskOutcomeAccepted
	}
	if bounded := appmcp.BoundTaskStatus(string(status)); bounded != "" {
		return string(bounded)
	}
	return trace.TaskOutcomeAccepted
}
