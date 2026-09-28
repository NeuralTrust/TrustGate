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

package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"log/slog"
	"maps"
	"net/http"
	"net/textproto"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const postResponseTimeout = 30 * time.Second

const maxPostResponseBufferBytes = 8 * 1024 * 1024

func (f *forwarder) runPreRequest(
	ctx context.Context,
	policies []*policy.Policy,
	plan *appplugins.StagePlan,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
) (*ForwardResult, error) {
	if f.executor == nil {
		return nil, nil
	}
	outcome, err := f.executor.RunStage(ctx, appplugins.StageInput{
		Stage:    policy.StagePreRequest,
		Policies: policies,
		Plan:     plan,
		Request:  req,
		Response: resp,
	})
	if err != nil {
		if pe, ok := appplugins.AsPluginError(err); ok {
			return pluginErrorResult(pe), nil
		}
		return nil, err
	}
	if outcome.ShortCircuit {
		return &ForwardResult{
			StatusCode: outcome.StatusCode,
			Headers:    outcome.Headers,
			Body:       outcome.Body,
		}, nil
	}
	return nil, nil
}

// checkRateLimit enforces the gateway plan burst/quota before the request
// reaches the upstream. An exceeded limit renders a 429 ForwardResult with the
// standard rate-limit headers; an unavailable plan (unknown/missing tier)
// propagates as an error so mapProxyError maps it to HTTP 503, matching how an
// unusable guard is treated.
func (f *forwarder) checkRateLimit(ctx context.Context, gatewayID ids.GatewayID) (*ForwardResult, error) {
	err := f.limiter.Check(ctx, gatewayID)
	if err == nil {
		return nil, nil
	}
	var exceeded *ratelimitapp.Exceeded
	if errors.As(err, &exceeded) {
		return &ForwardResult{
			StatusCode: http.StatusTooManyRequests,
			Headers:    exceeded.Headers(),
			Body:       exceeded.Body(),
		}, nil
	}
	return nil, err
}

// runPreResponseGated runs the pre_response stage and hands back both ways it
// can end the response: a PluginError, and the stage outcome a plugin's own
// StopUpstream result produces.
//
// The outcome has to be returned because only one of the two callers can read
// it off anything else. applyResults writes StatusCode, Body and Headers onto
// the ResponseContext, and finalizeBodyGated renders its ForwardResult from
// exactly that, so on the buffered leg a short circuit is already applied by
// the time this returns. finalizeStream renders from the provider response and
// forwards the upstream iterator, so there the same result reaches nothing:
// without this the stream would be sent unmodified under the provider's own
// status, and only a PluginError would ever stop it.
//
// No plugin in this repository produces that result on a stream today. Every
// output-inspecting plugin skips a streaming pre_response leg outright, and the
// ones that rewrite a body — regexreplace, googlemodelarmor, bedrockguardrail —
// have nothing to rewrite there, because mergeStreamingResponse copies status
// and headers and leaves the body empty. This is therefore a defensive fix with
// no live producer: the stage contract says a pre_response result can end the
// response, and one of the two legs was not honouring it.
func (f *forwarder) runPreResponseGated(
	ctx context.Context,
	policies []*policy.Policy,
	plan *appplugins.StagePlan,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
) (*appplugins.StageOutcome, *appplugins.PluginError) {
	if f.executor == nil {
		return nil, nil
	}
	outcome, err := f.executor.RunStage(ctx, appplugins.StageInput{
		Stage:    policy.StagePreResponse,
		Policies: policies,
		Plan:     plan,
		Request:  req,
		Response: resp,
	})
	if err != nil {
		if pe, ok := appplugins.AsPluginError(err); ok {
			return nil, pe
		}
		f.logger.Warn("pre_response plugin stage failed", slog.String("error", err.Error()))
		if preResponseBlocks(policies, plan) {
			return nil, &appplugins.PluginError{
				StatusCode: http.StatusBadGateway,
				Message:    "pre_response plugin stage failed",
			}
		}
	}
	return outcome, nil
}

func preResponseBlocks(policies []*policy.Policy, plan *appplugins.StagePlan) bool {
	if plan != nil {
		return plan.Blocks(policy.StagePreResponse)
	}
	for _, pol := range policies {
		if pol == nil || !pol.Enabled || !appplugins.Blocks(pol.Mode.Normalize()) {
			continue
		}
		if len(pol.Stages) == 0 {
			return true
		}
		for _, stage := range pol.Stages {
			if stage == policy.StagePreResponse {
				return true
			}
		}
	}
	return false
}

func hasPostResponse(plan *appplugins.StagePlan) bool {
	if plan == nil {
		return true
	}
	return plan.Has(policy.StagePostResponse)
}

func (f *forwarder) firePostResponse(
	ctx context.Context,
	policies []*policy.Policy,
	plan *appplugins.StagePlan,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
) {
	f.firePostResponseAfter(ctx, nil, policies, plan, req, resp)
}

// firePostResponseAfter runs the post_response stage once gate is closed, or
// immediately when there is no gate. The only gate there is today is the
// background drain a mid-stream cut leaves behind, and two things ride on it.
//
// The drain writes req.Metadata["usage"] from its own goroutine, so cloning the
// map before it has finished is a concurrent map read and write, not a stale
// number. And usage rides the last chunk, which on a cut is still upstream when
// the terminator reaches the client, so a token_rate_limiter reading the map
// before the drain ends charges a blocked stream nothing — the outcome the
// drain exists to prevent.
//
// The client never waits for any of this: the terminator was yielded before the
// drain started, and this stage has always been detached with a timeout of its
// own.
func (f *forwarder) firePostResponseAfter(
	ctx context.Context,
	gate <-chan struct{},
	policies []*policy.Policy,
	plan *appplugins.StagePlan,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
) {
	if f.executor == nil || !hasPostResponse(plan) {
		return
	}
	rt := trace.FromContext(ctx)
	respCopy := snapshotResponse(resp)
	var reqCopy *infracontext.RequestContext
	if gate == nil {
		reqCopy = snapshotRequest(req)
	}
	timeout := postResponseTimeout
	if gate != nil {
		timeout += cutDrainDeadline
	}

	if rt != nil {
		rt.AddAsync()
	}
	go func() { // #nosec G118 -- post-response must outlive the request context, which is cancelled once the response is sent; the goroutine owns its own timeout
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cancel()
		if rt != nil {
			defer rt.Done()
			ctx = trace.NewContext(ctx, rt)
		}
		if gate != nil {
			select {
			case <-gate:
			case <-ctx.Done():
				f.logger.Warn("post_response skipped: the cut drain outlived its deadline")
				return
			}
			reqCopy = snapshotRequest(req)
		}
		if _, err := f.executor.RunStage(ctx, appplugins.StageInput{
			Stage:    policy.StagePostResponse,
			Policies: policies,
			Plan:     plan,
			Request:  reqCopy,
			Response: respCopy,
		}); err != nil {
			f.logger.Warn("post_response plugin stage failed", slog.String("error", err.Error()))
		}
	}()
}

func (f *forwarder) wrapStreamWithPostResponse(
	ctx context.Context,
	policies []*policy.Policy,
	plan *appplugins.StagePlan,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	stream iter.Seq2[[]byte, error],
	gate func() <-chan struct{},
) iter.Seq2[[]byte, error] {
	if f.executor == nil || !hasPostResponse(plan) {
		return stream
	}
	return func(yield func([]byte, error) bool) {
		var body []byte
		completed := true
		truncated := false
		for line, err := range stream {

			if err == nil && len(line) > 0 && !truncated {
				if len(body)+len(line)+1 > maxPostResponseBufferBytes {
					truncated = true
				} else {
					body = append(body, line...)
					body = append(body, '\n')
				}
			}
			if !yield(line, err) {
				completed = false
				break
			}
		}

		if !completed {
			return
		}
		if truncated {
			f.logger.Warn("post_response skipped: streamed body exceeded buffer cap",
				slog.Int("cap_bytes", maxPostResponseBufferBytes))
			return
		}
		resp.Body = body
		// gate is consulted here rather than captured above because a cut
		// decides mid-stream: the guard installs the barrier on the goroutine
		// this loop has just finished draining, so it is readable now and was
		// not when the wrapper was built.
		var drained <-chan struct{}
		if gate != nil {
			drained = gate()
		}
		f.firePostResponseAfter(ctx, drained, policies, plan, req, resp)
	}
}

func drainStream(stream iter.Seq2[[]byte, error]) {
	if stream == nil {
		return
	}
	for range stream {
		break
	}
}

func pluginErrorResult(pe *appplugins.PluginError) *ForwardResult {
	body := pe.Body
	if body == nil {
		payload := map[string]string{
			"error":   "plugin_rejected",
			"message": pe.Message,
		}
		if pe.Type != "" {
			payload["type"] = pe.Type
		}
		body, _ = json.Marshal(payload)
	}
	headers := pe.Headers
	if len(body) > 0 && !hasResponseHeader(headers, "Content-Type") {
		headers = cloneResponseHeaders(headers)
		headers["Content-Type"] = []string{"application/json"}
	}
	return &ForwardResult{
		StatusCode: pe.StatusCode,
		Headers:    headers,
		Body:       body,
	}
}

func hasResponseHeader(headers map[string][]string, name string) bool {
	if len(headers) == 0 {
		return false
	}
	want := textproto.CanonicalMIMEHeaderKey(name)
	for k := range headers {
		if textproto.CanonicalMIMEHeaderKey(k) == want {
			return true
		}
	}
	return false
}

// setResponseHeader replaces name whatever case it was spelled in, so a value
// the gateway is correcting cannot end up beside the one it corrected.
func setResponseHeader(headers map[string][]string, name, value string) {
	deleteResponseHeader(headers, name)
	headers[textproto.CanonicalMIMEHeaderKey(name)] = []string{value}
}

func deleteResponseHeader(headers map[string][]string, name string) {
	want := textproto.CanonicalMIMEHeaderKey(name)
	for k := range headers {
		if textproto.CanonicalMIMEHeaderKey(k) == want {
			delete(headers, k)
		}
	}
}

func cloneResponseHeaders(headers map[string][]string) map[string][]string {
	if len(headers) == 0 {
		return map[string][]string{}
	}
	out := make(map[string][]string, len(headers))
	for k, vs := range headers {
		cp := make([]string, len(vs))
		copy(cp, vs)
		out[k] = cp
	}
	return out
}

func mergeStreamingResponse(resp *infracontext.ResponseContext, provider *ProviderResponse) {
	mergeResponseMeta(resp, provider)
	resp.Streaming = true
}

func mergeBufferedResponse(resp *infracontext.ResponseContext, provider *ProviderResponse) {
	mergeResponseMeta(resp, provider)
	resp.Streaming = false
	resp.Body = provider.Body
}

func mergeResponseMeta(resp *infracontext.ResponseContext, provider *ProviderResponse) {
	resp.StatusCode = provider.StatusCode
	if resp.Headers == nil {
		resp.Headers = make(map[string][]string, len(provider.Headers))
	}
	for name, values := range provider.Headers {
		resp.Headers[name] = append(resp.Headers[name], values...)
	}
}

func snapshotRequest(req *infracontext.RequestContext) *infracontext.RequestContext {
	if req == nil {
		return &infracontext.RequestContext{}
	}
	clone := *req
	clone.Body = append([]byte(nil), req.Body...)
	clone.Metadata = maps.Clone(req.Metadata)
	return &clone
}

func snapshotResponse(resp *infracontext.ResponseContext) *infracontext.ResponseContext {
	if resp == nil {
		return &infracontext.ResponseContext{}
	}
	clone := *resp
	clone.Body = append([]byte(nil), resp.Body...)
	clone.Headers = nil
	clone.Metadata = maps.Clone(resp.Metadata)
	return &clone
}

// cloneHeaders returns a deep copy of the header map so callers can reset a
// response's headers to a known baseline without aliasing the source slices.
func cloneHeaders(headers map[string][]string) map[string][]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string][]string, len(headers))
	for name, values := range headers {
		out[name] = append([]string(nil), values...)
	}
	return out
}
