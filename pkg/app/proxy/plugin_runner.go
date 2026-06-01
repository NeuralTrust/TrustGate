package proxy

import (
	"context"
	"encoding/json"
	"iter"
	"log/slog"
	"time"

	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics"
)

// postResponseTimeout bounds the detached PostResponse stage so a slow plugin
// (e.g. an embedding store) cannot leak goroutines indefinitely.
const postResponseTimeout = 30 * time.Second

// runPreRequest executes the PreRequest stage. It returns a non-nil
// *ForwardResult when the chain short-circuits (plugin rejection or cache hit),
// in which case the caller must relay it and skip the upstream.
func (f *forwarder) runPreRequest(
	ctx context.Context,
	policies []*policy.Policy,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
) (*ForwardResult, error) {
	if f.executor == nil {
		return nil, nil
	}
	outcome, err := f.executor.RunStage(ctx, appplugins.StageInput{
		Stage:     policy.StagePreRequest,
		Policies:  policies,
		Request:   req,
		Response:  resp,
		Collector: metrics.CollectorFromContext(ctx),
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

// runPreResponse executes the PreResponse stage, merging plugin headers into the
// response. Short-circuits are not expected at this stage and are ignored.
func (f *forwarder) runPreResponse(
	ctx context.Context,
	policies []*policy.Policy,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
) {
	if f.executor == nil {
		return
	}
	if _, err := f.executor.RunStage(ctx, appplugins.StageInput{
		Stage:     policy.StagePreResponse,
		Policies:  policies,
		Request:   req,
		Response:  resp,
		Collector: metrics.CollectorFromContext(ctx),
	}); err != nil {
		f.logger.Warn("pre_response plugin stage failed", slog.String("error", err.Error()))
	}
}

// firePostResponse runs the PostResponse stage asynchronously against snapshots
// of the request/response so it never races the client response that is being
// relayed concurrently.
func (f *forwarder) firePostResponse(
	policies []*policy.Policy,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
) {
	if f.executor == nil {
		return
	}
	collector := metrics.CollectorFromContext(req.Context)
	reqCopy := snapshotRequest(req)
	respCopy := snapshotResponse(resp)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), postResponseTimeout)
		defer cancel()
		if _, err := f.executor.RunStage(ctx, appplugins.StageInput{
			Stage:     policy.StagePostResponse,
			Policies:  policies,
			Request:   reqCopy,
			Response:  respCopy,
			Collector: collector,
		}); err != nil {
			f.logger.Warn("post_response plugin stage failed", slog.String("error", err.Error()))
		}
	}()
}

// wrapStreamWithPostResponse returns a stream that yields the same lines while
// accumulating the body, firing PostResponse once the upstream stream is fully
// drained.
func (f *forwarder) wrapStreamWithPostResponse(
	policies []*policy.Policy,
	req *infracontext.RequestContext,
	resp *infracontext.ResponseContext,
	stream iter.Seq2[[]byte, error],
) iter.Seq2[[]byte, error] {
	if f.executor == nil {
		return stream
	}
	return func(yield func([]byte, error) bool) {
		var body []byte
		completed := true
		for line, err := range stream {
			// Accumulate only successful, non-empty lines so the reconstructed
			// body mirrors the upstream payload without the SSE separator noise
			// (matches TrustGate's stream buffering for PostResponse).
			if err == nil && len(line) > 0 {
				body = append(body, line...)
				body = append(body, '\n')
			}
			if !yield(line, err) {
				completed = false
				break
			}
		}
		// Skip PostResponse when the consumer aborted (client disconnect / write
		// error): the stream never finished, so usage/body are incomplete.
		if completed {
			resp.Body = body
			f.firePostResponse(policies, req, resp)
		}
	}
}

// pluginErrorResult turns a plugin rejection into a relayable response,
// preserving the plugin's status and headers.
func pluginErrorResult(pe *appplugins.PluginError) *ForwardResult {
	body, _ := json.Marshal(map[string]string{
		"error":   "plugin_rejected",
		"message": pe.Message,
	})
	return &ForwardResult{
		StatusCode: pe.StatusCode,
		Headers:    pe.Headers,
		Body:       body,
	}
}

// mergeProviderResponse folds the upstream response into the plugin response
// context so PostResponse plugins observe the final status, headers and body.
func mergeProviderResponse(resp *infracontext.ResponseContext, provider *ProviderResponse, streaming bool) {
	resp.StatusCode = provider.StatusCode
	resp.Streaming = streaming
	if !streaming {
		resp.Body = provider.Body
	}
	if resp.Headers == nil {
		resp.Headers = make(map[string][]string, len(provider.Headers))
	}
	for name, values := range provider.Headers {
		resp.Headers[name] = append(resp.Headers[name], values...)
	}
}

func snapshotRequest(req *infracontext.RequestContext) *infracontext.RequestContext {
	if req == nil {
		return &infracontext.RequestContext{Context: context.Background()}
	}
	clone := *req
	clone.Context = context.Background()
	clone.Body = append([]byte(nil), req.Body...)
	clone.Metadata = copyMetadata(req.Metadata)
	return &clone
}

func snapshotResponse(resp *infracontext.ResponseContext) *infracontext.ResponseContext {
	if resp == nil {
		return &infracontext.ResponseContext{}
	}
	clone := *resp
	clone.Context = context.Background()
	clone.Body = append([]byte(nil), resp.Body...)
	clone.Headers = nil // PostResponse headers are post-hoc and not relayed.
	clone.Metadata = copyMetadata(resp.Metadata)
	return &clone
}

func copyMetadata(in map[string]interface{}) map[string]interface{} {
	if in == nil {
		return nil
	}
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
