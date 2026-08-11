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

func (f *forwarder) runPreResponseGated(
	ctx context.Context,
	policies []*policy.Policy,
	plan *appplugins.StagePlan,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
) *appplugins.PluginError {
	if f.executor == nil {
		return nil
	}
	if _, err := f.executor.RunStage(ctx, appplugins.StageInput{
		Stage:    policy.StagePreResponse,
		Policies: policies,
		Plan:     plan,
		Request:  req,
		Response: resp,
	}); err != nil {
		if pe, ok := appplugins.AsPluginError(err); ok {
			return pe
		}
		f.logger.Warn("pre_response plugin stage failed", slog.String("error", err.Error()))
		if preResponseBlocks(policies, plan) {
			return &appplugins.PluginError{
				StatusCode: http.StatusBadGateway,
				Message:    "pre_response plugin stage failed",
			}
		}
	}
	return nil
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
	if f.executor == nil || !hasPostResponse(plan) {
		return
	}
	rt := trace.FromContext(ctx)
	reqCopy := snapshotRequest(req)
	respCopy := snapshotResponse(resp)

	if rt != nil {
		rt.AddAsync()
	}
	go func() { // #nosec G118 -- post-response must outlive the request context, which is cancelled once the response is sent; the goroutine owns its own timeout
		ctx, cancel := context.WithTimeout(context.Background(), postResponseTimeout)
		defer cancel()
		if rt != nil {
			defer rt.Done()
			ctx = trace.NewContext(ctx, rt)
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
		f.firePostResponse(ctx, policies, plan, req, resp)
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
