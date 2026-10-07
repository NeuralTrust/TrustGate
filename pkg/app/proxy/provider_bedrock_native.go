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
	"fmt"
	"iter"
	"log/slog"
	"net/http"

	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// invokeBedrockNative relays a Bedrock Runtime request to the registry as the
// client sent it. It deliberately skips prepare: no format adaptation, no model
// enforcement rewrite, no output clamp, no stream flag, no retry with another
// body. The model is checked read-only against the allow-list, and everything
// AWS answers, errors included, goes back as a response and not as an error, so
// classification and failover treat it like any other backend answer.
func (p *providerInvoker) invokeBedrockNative(
	ctx context.Context,
	bk *registry.Registry,
	req *infracontext.RequestContext,
) (*ProviderResponse, error) {
	target := req.BedrockNative
	// Routing already restricts a native request to Bedrock registries; this is
	// the second lock, so no code path ever hands the call to another provider.
	if bk.Provider() != provider.Bedrock {
		return nil, fmt.Errorf("%w: application has no Amazon Bedrock registry", routingdomain.ErrNoRegistryServesModel)
	}
	if err := adapter.CheckAllowedModel(target.ModelID, req.AllowedModels); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrModelNotAllowed, err.Error())
	}
	client, err := p.locator.Get(bk.Provider())
	if err != nil {
		return nil, fmt.Errorf("resolve provider client: %w", err)
	}
	native, ok := client.(providers.NativeBedrockClient)
	if !ok {
		return nil, fmt.Errorf("%w: native bedrock", ErrCapabilityNotSupported)
	}

	// Usage belongs to one attempt. Reset here, before the call, so a failover
	// never charges what an earlier attempt reported, and a stream's observer
	// never merges into it.
	delete(req.Metadata, adapter.MetadataUsageKey)

	req.Provider = bk.Provider()
	req.SourceFormat = string(adapter.FormatBedrockNative)
	req.TargetFormat = string(adapter.FormatBedrock)

	route := adapter.BedrockNativeRoute{
		Op:         adapter.BedrockNativeOp(target.Op),
		RawModelID: target.RawModelID,
		ModelID:    target.ModelID,
	}
	path, rawPath := route.UpstreamPath()
	stream := route.IsStream()
	// The client's own Authorization is a SigV4 signature for credentials the
	// gateway does not hold, so it never seeds the registry credentials.
	cfg := &providers.Config{Credentials: registryCredentials(bk, ""), Model: target.ModelID}
	nativeReq := providers.NativeBedrockRequest{
		Path:    path,
		RawPath: rawPath,
		Stream:  stream,
		Body:    req.Body,
		Headers: http.Header(req.Headers),

		MaxResponseBytes: p.nativeMaxResponseBytes,
	}

	resolved := resolveNativeModelID(ctx, p.models, bk, target.ModelID)
	if resolved != "" {
		req.ResolvedModel = resolved
	} else {
		// The forwarder may have resolved it before the pre_request stage.
		resolved = req.ResolvedModel
	}

	callCtx := ctx
	cancel := func() {}
	if stream {
		callCtx, cancel = context.WithCancel(ctx)
	}
	resp, err := native.InvokeNative(callCtx, cfg, nativeReq)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("provider bedrock native: %w", err)
	}
	headers := withSelectionHeaders(nativeHeaders(resp.Headers), bk, target.ModelID)

	if resolved == "" {
		// A lookup the call itself started may have finished by now; it is only
		// ever read here, never waited on.
		resolved = resolveNativeModelID(ctx, p.models, bk, target.ModelID)
		req.ResolvedModel = resolved
	}
	// The span names the model that served the call: the resolved one when it is
	// known, else the identifier the client sent. SentModel stays the literal.
	model := resolved
	if model == "" {
		model = target.ModelID
	}

	if resp.Frames != nil {
		return &ProviderResponse{
			StatusCode: resp.StatusCode,
			Headers:    headers,
			Stream:     p.nativeFrameStream(callCtx, bk, req, resp.Frames, cancel),
			Model:      model,
			SentModel:  target.ModelID,
			RawFrames:  true,
			StreamView: adapter.BedrockFrameView,
		}, nil
	}
	cancel()
	out := &ProviderResponse{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       resp.Body,
		Model:      model,
		SentModel:  target.ModelID,
	}
	if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
		p.observeNativeBody(req, route, resp, out)
	}
	return out, nil
}

func nativeHeaders(in http.Header) map[string][]string {
	out := make(map[string][]string, len(in)+1)
	for name, values := range in {
		out[name] = append([]string(nil), values...)
	}
	if _, ok := out[headerContentType]; !ok {
		out[headerContentType] = []string{contentTypeJSON}
	}
	return out
}

// observeNativeBody reads usage, finish reason and id off a buffered answer for
// the span, cost and token budgets. The body is only read, never rewritten.
func (p *providerInvoker) observeNativeBody(
	req *infracontext.RequestContext,
	route adapter.BedrockNativeRoute,
	resp *providers.NativeBedrockResponse,
	out *ProviderResponse,
) {
	usage, _, finish, id := p.decodeResponseMeta(resp.Body, adapter.FormatBedrockNative)
	if !route.Op.IsConverse() {
		// The headers carry the cache buckets and the body may carry more
		// than the headers do, so neither replaces the other.
		usage = adapter.MergeUsage(usage, adapter.BedrockUsageFromHeaders(resp.Headers))
	}
	out.Usage, out.FinishReason, out.ResponseID = usage, finish, id
	if usage == nil {
		return
	}
	if req.Metadata == nil {
		req.Metadata = map[string]interface{}{}
	}
	req.Metadata[adapter.MetadataUsageKey] = usage
}

func (p *providerInvoker) nativeFrameStream(
	ctx context.Context,
	bk *registry.Registry,
	req *infracontext.RequestContext,
	frames iter.Seq2[[]byte, error],
	cancel context.CancelFunc,
) iter.Seq2[[]byte, error] {
	observe := p.streamObserver(ctx, req)
	nativeFormat := adapter.FormatBedrockNative
	return func(yield func([]byte, error) bool) {
		defer cancel()
		for frame, err := range frames {
			if err != nil {
				p.logger.Debug("native bedrock stream ended with an error", slog.String("error", err.Error()))
				yield(nil, err)
				return
			}
			for _, line := range adapter.BedrockFrameView(frame) {
				if payload, ok := dataPayload(line); ok {
					observeChunk(p.registry, payload, nativeFormat, observe)
				}
			}
			if !yield(frame, nil) {
				return
			}
		}
	}
}
