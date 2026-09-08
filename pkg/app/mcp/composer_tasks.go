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
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
)

// wrapTask replaces the upstream taskId with a signed handle. When task
// mediation is off the task shape is stripped instead, so a client is never
// handed an id it has no way to poll.
func (c *composer) wrapTask(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	b binding,
	call ToolCall,
	result json.RawMessage,
) (json.RawMessage, error) {
	if !c.tasks.Enabled() {
		return StripTaskResult(result), nil
	}
	var task Task
	if err := json.Unmarshal(result, &task); err != nil || task.TaskID == "" {
		return StripTaskResult(result), nil
	}
	gatewayID, consumerID := "", ""
	if rc != nil && rc.Consumer != nil {
		gatewayID = rc.Consumer.GatewayID.String()
		consumerID = rc.Consumer.ID.String()
	}
	registryID := ""
	if b.registry != nil {
		registryID = b.registry.ID.String()
	}
	created := time.Now().Unix()
	handle, err := c.tasks.Mint(TaskHandleClaims{
		GID:      gatewayID,
		CID:      consumerID,
		RID:      registryID,
		Sub:      principalFingerprint(ctx),
		Exposed:  call.Name,
		Upstream: b.tool.Name,
		TaskID:   task.TaskID,
		Created:  created,
		Exp:      upstreamTaskDeadline(created, task.TTLMs),
	})
	if err != nil {
		return nil, MapTaskError(err)
	}
	return RewriteTaskEnvelope(result, handle, c.pollFloorMs), nil
}

// upstreamTaskDeadline is the wall-clock second the upstream's own ttlMs runs
// out, or 0 when it declared none.
func upstreamTaskDeadline(createdAt int64, ttlMs *int64) int64 {
	if ttlMs == nil || *ttlMs <= 0 {
		return 0
	}
	return createdAt + *ttlMs/1000
}

// UnwrapTaskHandle verifies the handle's MAC, expiry, and caller binding without
// composing or dialling, so the dispatcher can recover the exposed tool name for
// the plugin stages before any upstream work happens. The registry-attachment
// and toolkit assertions stay inside the use cases; both paths answer with the
// same sentinel, so the split leaks nothing.
func (c *composer) UnwrapTaskHandle(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	handle string,
) (TaskRef, error) {
	claims, err := c.unwrapTaskClaims(ctx, rc, handle)
	if err != nil {
		return TaskRef{}, err
	}
	return taskRef(claims), nil
}

func (c *composer) GetTask(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	handle string,
) (json.RawMessage, error) {
	ref, up, closeUp, err := c.resolveTask(ctx, rc, handle)
	if err != nil {
		return nil, err
	}
	defer closeUp()
	result, err := up.GetTask(ctx, ref)
	if err != nil {
		return nil, ErrTaskHandleRejected
	}
	return c.echoHandle(result, handle), nil
}

func (c *composer) UpdateTask(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	handle string,
	inputResponses json.RawMessage,
) (json.RawMessage, error) {
	ref, up, closeUp, err := c.resolveTask(ctx, rc, handle)
	if err != nil {
		return nil, err
	}
	defer closeUp()
	result, err := up.UpdateTask(ctx, ref, inputResponses)
	if err != nil {
		return nil, ErrTaskHandleRejected
	}
	return c.echoHandle(result, handle), nil
}

func (c *composer) CancelTask(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	handle string,
) (json.RawMessage, error) {
	ref, up, closeUp, err := c.resolveTask(ctx, rc, handle)
	if err != nil {
		return nil, err
	}
	defer closeUp()
	result, err := up.CancelTask(ctx, ref)
	if err != nil {
		return nil, ErrTaskHandleRejected
	}
	return c.echoHandle(result, handle), nil
}

// echoHandle returns the inbound handle in the response rather than minting a
// new one, so a handle stays stable for the task's whole life. A payload that
// carries no taskId (a cancel ack) is passed through untouched.
func (c *composer) echoHandle(result json.RawMessage, handle string) json.RawMessage {
	if len(result) == 0 {
		return result
	}
	if _, _, taskID, ok := TaskResultFields(result); !ok || taskID == "" {
		return result
	}
	return RewriteTaskEnvelope(result, handle, c.pollFloorMs)
}

// resolveTask runs the full re-authorization pass and dials only the registry
// the handle was minted against. Every failure — a bad MAC, expiry, a detached
// registry, a toolkit that no longer maps the tool, a principal change, an
// unresolvable credential, or an upstream that cannot serve tasks — collapses
// into ErrTaskHandleRejected.
func (c *composer) resolveTask(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	handle string,
) (TaskRef, TaskUpstream, func(), error) {
	noop := func() {}
	claims, err := c.unwrapTaskClaims(ctx, rc, handle)
	if err != nil {
		return TaskRef{}, nil, noop, err
	}
	comp, err := c.compose(ctx, rc)
	if err != nil {
		return TaskRef{}, nil, noop, ErrTaskHandleRejected
	}
	bound, ok := c.boundBinding(rc, comp, claims)
	if !ok {
		return TaskRef{}, nil, noop, ErrTaskHandleRejected
	}
	target, err := c.target(ctx, rc, bound.registry)
	if err != nil {
		return TaskRef{}, nil, noop, ErrTaskHandleRejected
	}
	stop := annotateUpstream(ctx, bound.registry, bound.tool.Name)
	up, err := c.dialer.Connect(ctx, target)
	if err != nil {
		stop()
		return TaskRef{}, nil, noop, ErrTaskHandleRejected
	}
	taskUp, ok := up.(TaskUpstream)
	if !ok {
		up.Close(ctx)
		stop()
		return TaskRef{}, nil, noop, ErrTaskHandleRejected
	}
	return taskRef(claims), taskUp, func() {
		up.Close(ctx)
		stop()
	}, nil
}

func (c *composer) unwrapTaskClaims(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	handle string,
) (*TaskHandleClaims, error) {
	if !c.tasks.Enabled() || rc == nil || rc.Consumer == nil {
		return nil, ErrTaskHandleRejected
	}
	claims, err := c.tasks.Unwrap(handle)
	if err != nil {
		return nil, ErrTaskHandleRejected
	}
	if claims.GID != rc.Consumer.GatewayID.String() ||
		claims.CID != rc.Consumer.ID.String() ||
		claims.Sub != principalFingerprint(ctx) {
		return nil, ErrTaskHandleRejected
	}
	return claims, nil
}

// boundBinding finds the composed binding the handle names, asserting both that
// the registry is still attached to the consumer and that the toolkit still maps
// the exposed name to the same upstream tool on it.
func (c *composer) boundBinding(
	rc *appconsumer.RoutableConsumer,
	comp *composition,
	claims *TaskHandleClaims,
) (binding, bool) {
	attached := false
	for _, reg := range mcpRegistries(rc) {
		if reg.ID.String() == claims.RID {
			attached = true
			break
		}
	}
	if !attached {
		return binding{}, false
	}
	for _, b := range comp.bindings {
		if b.registry == nil || b.registry.ID.String() != claims.RID {
			continue
		}
		if b.exposed == claims.Exposed && b.tool.Name == claims.Upstream {
			return b, true
		}
	}
	return binding{}, false
}

func taskRef(claims *TaskHandleClaims) TaskRef {
	return TaskRef{
		RegistryID: claims.RID,
		Exposed:    claims.Exposed,
		Upstream:   claims.Upstream,
		TaskID:     claims.TaskID,
		Exp:        claims.Exp,
	}
}
