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
	"bytes"
	"context"
	"fmt"
	"github.com/NeuralTrust/TrustGate/pkg/domain/bedrocknative"
	"iter"
	"net/http"
	"strings"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

// The messages of what a native call refuses: a policy answering for Bedrock, with
// a canned answer or a status of its own, which is not a mask.
const (
	nativeResponseModified = "policy would answer the response itself; native Bedrock responses are relayed as AWS gave them"
	nativeShortCircuited   = "policy answered the request itself; native Bedrock requests are always relayed to Bedrock"
)

func nativeBodySnapshot(req *infracontext.RequestContext) []byte {
	if !req.IsBedrockNative() {
		return nil
	}
	return append([]byte{}, req.Body...)
}

func nativeModified(message string) *appplugins.PluginError {
	return &appplugins.PluginError{
		StatusCode: http.StatusForbidden,
		Message:    message,
		Type:       appplugins.BedrockNativePassthrough,
	}
}

func nativeShortCircuit(req *infracontext.RequestContext, short *ForwardResult, stage policydomain.Stage) *ForwardResult {
	if short == nil || !req.IsBedrockNative() || short.StatusCode >= http.StatusBadRequest {
		return short
	}
	return pluginErrorResult(appplugins.WithBlockDirection(
		nativeModified(nativeShortCircuited), appplugins.BlockDirectionForStage(stage)))
}

func nativeResponseChanged(provider *ProviderResponse, plugin *infracontext.ResponseContext) bool {
	return plugin.StatusCode != provider.StatusCode || !bytes.Equal(plugin.Body, provider.Body)
}

// nativeAccessDenied reports an AWS AccessDeniedException answer to a native
// call. "You don't have access to the model" is how a Bedrock account that has
// not enabled a model answers, which another registry, with another account,
// may well have, so it counts as a miss for the probing over Bedrock
// registries. It is scoped to native calls: elsewhere a 403 stays terminal. If
// every registry misses, the last AWS answer is relayed as it came.
func nativeAccessDenied(req *infracontext.RequestContext, resp *ProviderResponse) bool {
	if !req.IsBedrockNative() || resp == nil {
		return false
	}
	for name, values := range resp.Headers {
		if !strings.EqualFold(name, adapter.HeaderAmznErrorType) {
			continue
		}
		for _, v := range values {
			if strings.HasPrefix(strings.ToLower(v), "accessdeniedexception") {
				return true
			}
		}
	}
	return false
}

// resolveOpaqueNativeModel names the model behind an application inference
// profile or provisioned throughput ARN before the pre_request stage, so a cost
// cap and the token budgets price the call on its first use. A cached answer
// costs nothing, a negative entry does not wait, concurrent first calls share one
// control plane call, and a timeout or a failure leaves the call unresolved:
// the lookup never fails a request. Other requests are untouched.
func (f *forwarder) resolveOpaqueNativeModel(
	ctx context.Context,
	bk *registrydomain.Registry,
	req *infracontext.RequestContext,
) {
	if f.models == nil || !req.IsBedrockNative() || bk == nil {
		return
	}
	arn := req.BedrockNative.ModelID
	if _, opaque := bedrocknative.ParseOpaqueBedrockARN(arn); !opaque {
		return
	}
	if id, ok := f.models.Resolve(ctx, bk, arn, f.nativeLookupWait); ok {
		req.ResolvedModel = id
	}
}

// NativeBodyMasker carries what a masking policy changed onto the bytes a native
// call was sent with, or says why it cannot. adapter.NativeMasker is the one
// implementation; tests substitute one that fails.
type NativeBodyMasker interface {
	MaskRequestWhy(original, modified []byte) ([]byte, adapter.MaskCause)
	MaskResponseWhy(original, modified []byte) ([]byte, adapter.MaskCause)
}

var _ NativeBodyMasker = adapter.NativeMasker{}

// carryNativeMask is the one place that decides what becomes of a change a policy
// made to a native call. A change no plugin declared as a mask is not one, and is
// refused. A mask is carried onto the original bytes; if that cannot be done
// safely the call is refused, recorded as blocked with its cause: the original
// would carry what the policy asked to mask, so there is no unmasked call to
// let through.
func (f *forwarder) carryNativeMask(
	ctx context.Context,
	stage policydomain.Stage,
	req *infracontext.RequestContext,
	original, changed []byte,
	mask func(original, modified []byte) ([]byte, adapter.MaskCause),
) ([]byte, *appplugins.PluginError) {
	sources := req.NativeMask.Sources(stage)
	if len(sources) == 0 {
		return nil, appplugins.NativeRewriteRefusal("a policy", stage)
	}
	masked, cause := mask(original, changed)
	if cause == "" {
		return masked, nil
	}
	appplugins.RecordNativeMaskBlocked(ctx, f.logger, stage, cause, false)
	return nil, appplugins.WithBlockDirection(
		nativeMaskBlocked(sources[0].Plugin, cause), appplugins.BlockDirectionForStage(stage))
}

func nativeMaskBlocked(plugin string, cause adapter.MaskCause) *appplugins.PluginError {
	return &appplugins.PluginError{
		StatusCode: http.StatusForbidden,
		Type:       appplugins.BedrockNativePassthrough,
		Message:    fmt.Sprintf("policy %s could not mask the call (%s); the call is refused", plugin, cause),
	}
}

// resolveNativeModelID names the model behind a native identifier when that can be
// known without waiting: a system profile or foundation model ARN carries it, and
// an opaque ARN is answered from the lookup cache, which a miss starts in the
// background. A plain model ID needs none and returns "".
func resolveNativeModelID(ctx context.Context, models appcatalog.BedrockModelResolver, bk *registrydomain.Registry, modelID string) string {
	arn, ok := bedrocknative.ParseBedrockARN(modelID)
	if !ok {
		return ""
	}
	if id, ok := arn.ModelID(); ok {
		return id
	}
	if arn.Opaque() && models != nil {
		if id, ok := models.Lookup(ctx, bk, modelID); ok {
			return id
		}
	}
	return ""
}

// refreshNativeModel names the model of a native call whose lookup finished while
// its stream was running. It runs on the goroutine that ends the stream, before
// post_response and the metrics event are built, so nothing reads the model
// while it is written: the only other writes are made before the call starts.
func (f *forwarder) refreshNativeModel(ctx context.Context, dto *forwardRequestDTO) {
	req := dto.request
	if !req.IsBedrockNative() || req.ResolvedModel != "" || dto.backend == nil {
		return
	}
	if id := resolveNativeModelID(ctx, f.models, dto.backend, req.BedrockNative.ModelID); id != "" {
		req.ResolvedModel = id
		if rt := trace.FromContext(ctx); rt != nil {
			rt.ObserveLLMResult(id, "")
		}
	}
}

func (f *forwarder) refreshModelAtStreamEnd(ctx context.Context, dto *forwardRequestDTO, stream iter.Seq2[[]byte, error]) iter.Seq2[[]byte, error] {
	if !dto.request.IsBedrockNative() || stream == nil {
		return stream
	}
	return func(yield func([]byte, error) bool) {
		defer f.refreshNativeModel(ctx, dto)
		for item, err := range stream {
			if !yield(item, err) {
				return
			}
		}
	}
}
