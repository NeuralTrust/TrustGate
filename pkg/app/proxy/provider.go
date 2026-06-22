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
	"fmt"
	"iter"
	"log/slog"
	"net/http"
	"strings"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/factory"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/trace"
)

const (
	headerSelectedProvider = "X-Selected-Provider"
	headerContentType      = "Content-Type"
	contentTypeJSON        = "application/json"

	responsesTurnIDPrefix = "resp_"
	fieldPreviousResponse = "previous_response_id"
)

var ErrInvalidRequestPayload = errors.New("invalid request payload")

var ErrModelNotAllowed = errors.New("model not allowed")


type ProviderResponse struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
	// Stream, when non-nil, yields SSE lines (without trailing newline) already
	// adapted to the client's source format. The consumer writes each line + "\n"
	// and is responsible for draining the sequence (which closes the backend
	// body). The second value carries mid-stream errors.
	Stream iter.Seq2[[]byte, error]
	Usage  *adapter.CanonicalUsage
	// Model is the model echoed by the provider in its response. Some providers
	// (e.g. Bedrock Titan/Llama/Mistral) leave it empty.
	Model string
	// SentModel is the model the gateway actually put on the outbound request to
	// the provider, after routing-ref parsing, pool/LB resolution and model
	// enforcement. It is the most reliable identifier for cost attribution.
	SentModel    string
	FinishReason string
	ResponseID   string
}

//go:generate mockery --name=ProviderInvoker --dir=. --output=./mocks --filename=provider_invoker_mock.go --case=underscore --with-expecter
type ProviderInvoker interface {
	Invoke(ctx context.Context, bk *registry.Registry, req *infracontext.RequestContext) (*ProviderResponse, error)
	InvokeStream(ctx context.Context, bk *registry.Registry, req *infracontext.RequestContext) (*ProviderResponse, error)
}

var _ ProviderInvoker = (*providerInvoker)(nil)

type providerInvoker struct {
	locator  factory.ProviderLocator
	registry *adapter.Registry
	logger   *slog.Logger
}

func NewProviderInvoker(
	locator factory.ProviderLocator,
	registry *adapter.Registry,
	logger *slog.Logger,
) ProviderInvoker {
	return &providerInvoker{
		locator:  locator,
		registry: registry,
		logger:   logger,
	}
}

// preparedInvocation is the shared result of resolving the provider client and
// transforming the request payload, used by both the synchronous and streaming
// paths.
type preparedInvocation struct {
	client       providers.Client
	cfg          *providers.Config
	body         []byte
	sentModel    string
	sourceFormat adapter.Format
	targetFormat adapter.Format
	crossFormat  bool
}

func (p *providerInvoker) Invoke(
	ctx context.Context,
	bk *registry.Registry,
	req *infracontext.RequestContext,
) (*ProviderResponse, error) {
	prep, err := p.prepare(bk, req)
	if err != nil {
		return nil, err
	}

	respBody, err := prep.client.Completions(ctx, prep.cfg, prep.body)
	if err != nil {
		if be, ok := registry.IsBackendError(err); ok {
			return &ProviderResponse{
				StatusCode: be.StatusCode,
				Headers:    be.PassthroughHeaders(),
				Body:       be.Body,
			}, nil
		}
		return nil, fmt.Errorf("provider completions: %w", err)
	}

	usage, model, finishReason, responseID := p.decodeResponseMeta(respBody, prep.targetFormat)

	if prep.crossFormat {
		if adapted, aerr := p.registry.AdaptResponse(respBody, prep.sourceFormat, prep.targetFormat); aerr != nil {
			p.logger.Warn("failed to adapt response, returning raw",
				slog.String("error", aerr.Error()))
		} else {
			respBody = adapted
		}
	}

	return &ProviderResponse{
		StatusCode: http.StatusOK,
		Headers: map[string][]string{
			headerSelectedProvider: {bk.Provider()},
			headerContentType:      {contentTypeJSON},
		},
		Body:         respBody,
		Usage:        usage,
		Model:        model,
		SentModel:    prep.sentModel,
		FinishReason: finishReason,
		ResponseID:   responseID,
	}, nil
}

func (p *providerInvoker) decodeResponseMeta(body []byte, format adapter.Format) (*adapter.CanonicalUsage, string, string, string) {
	canonical, err := p.registry.DecodeResponseFor(body, format)
	if err != nil || canonical == nil {
		return nil, "", "", ""
	}
	return canonical.Usage, canonical.Model, canonical.FinishReason, canonical.ID
}

func (p *providerInvoker) InvokeStream(
	ctx context.Context,
	bk *registry.Registry,
	req *infracontext.RequestContext,
) (*ProviderResponse, error) {
	prep, err := p.prepare(bk, req)
	if err != nil {
		return nil, err
	}

	body := prep.body
	// Registries speaking the OpenAI-style API need an explicit "stream": true even
	// when the source format (e.g. Gemini) does not carry it in the body.
	if adapter.IsSameWireFormat(prep.targetFormat, adapter.FormatOpenAI) ||
		prep.targetFormat == adapter.FormatOpenAIResponses ||
		prep.targetFormat == adapter.FormatAnthropic ||
		prep.targetFormat == adapter.FormatMistral {
		body = injectStreamTrue(body)
	}

	if adapter.IsSameWireFormat(prep.targetFormat, adapter.FormatOpenAI) {
		body = injectStreamIncludeUsage(body)
	}

	seq, err := prep.client.CompletionsStream(ctx, prep.cfg, body)
	if err != nil {
		if be, ok := registry.IsBackendError(err); ok {
			return &ProviderResponse{
				StatusCode: be.StatusCode,
				Headers:    be.PassthroughHeaders(),
				Body:       be.Body,
			}, nil
		}
		return nil, fmt.Errorf("provider completions stream: %w", err)
	}

	stream := adaptStream(seq, p.registry, prep.sourceFormat, prep.targetFormat, p.logger, p.streamObserver(ctx))

	return &ProviderResponse{
		StatusCode: http.StatusOK,
		Headers:    streamHeaders(bk.Provider()),
		Stream:     stream,
		SentModel:  prep.sentModel,
	}, nil
}

// prepare resolves the provider client and transforms the request payload across
// provider formats when needed, mutating req with the resolved format metadata.
func (p *providerInvoker) prepare(
	bk *registry.Registry,
	req *infracontext.RequestContext,
) (*preparedInvocation, error) {
	client, err := p.locator.Get(bk.Provider())
	if err != nil {
		return nil, fmt.Errorf("resolve provider client: %w", err)
	}

	sourceFormat := sourceFormatFromRequest(req)
	targetFormat := adapter.ResolveTargetFormat(bk.Provider(), bk.ProviderOptions())

	req.Provider = bk.Provider()
	req.SourceFormat = string(sourceFormat)
	req.TargetFormat = string(targetFormat)

	crossFormat := !adapter.ShouldPassthroughSameWireFormat(sourceFormat, targetFormat)

	body := req.Body
	if crossFormat {
		body, err = p.registry.AdaptRequest(req.Body, sourceFormat, targetFormat)
		if err != nil {
			if adapter.IsRequestDecodeError(err) {
				return nil, fmt.Errorf("%w: %s", ErrInvalidRequestPayload, err.Error())
			}
			return nil, fmt.Errorf("adapt request (%s->%s): %w", sourceFormat, targetFormat, err)
		}
	}

	body = adapter.NormalizeRequestForProvider(bk.Provider(), targetFormat, body)

	normalized, _, verr := adapter.EnforceModel(body, req.AllowedModels, req.DefaultModel)
	if verr != nil {
		if errors.Is(verr, adapter.ErrModelNotAllowed) {
			return nil, fmt.Errorf("%w: %s", ErrModelNotAllowed, verr.Error())
		}
		if len(req.AllowedModels) > 0 {
			return nil, fmt.Errorf("%w: model enforcement could not parse request body: %s", ErrModelNotAllowed, verr.Error())
		}
		p.logger.Warn("model enforcement failed, proceeding without override",
			slog.String("error", verr.Error()))
	} else {
		body = normalized
	}

	body = injectPreviousResponseID(body, targetFormat, req.PreviousResponseID)

	sentModel, _ := adapter.ExtractModel(body)

	return &preparedInvocation{
		client: client,
		cfg: &providers.Config{
			Options:     bk.ProviderOptions(),
			Credentials: bk.Auth().ProviderCredentials(),
		},
		body:         body,
		sentModel:    sentModel,
		sourceFormat: sourceFormat,
		targetFormat: targetFormat,
		crossFormat:  crossFormat,
	}, nil
}

func injectPreviousResponseID(body []byte, targetFormat adapter.Format, previousResponseID string) []byte {
	if previousResponseID == "" ||
		targetFormat != adapter.FormatOpenAIResponses ||
		!strings.HasPrefix(previousResponseID, responsesTurnIDPrefix) {
		return body
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	if _, exists := obj[fieldPreviousResponse]; exists {
		return body
	}
	raw, err := json.Marshal(previousResponseID)
	if err != nil {
		return body
	}
	obj[fieldPreviousResponse] = raw
	merged, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return merged
}

func (p *providerInvoker) streamObserver(ctx context.Context) func(*adapter.CanonicalStreamChunk) {
	requestTrace := trace.FromContext(ctx)
	return func(chunk *adapter.CanonicalStreamChunk) {
		if chunk == nil || requestTrace == nil {
			return
		}
		requestTrace.ObserveLLMResult(chunk.Model, chunk.FinishReason)
		requestTrace.ObserveLLMTurnID(chunk.ID)
		if chunk.Usage == nil {
			return
		}
		requestTrace.ObserveLLMUsage(chunk.Usage)
		p.logger.Debug("stream usage observed",
			slog.Int("input_tokens", chunk.Usage.InputTokens),
			slog.Int("output_tokens", chunk.Usage.OutputTokens),
			slog.Int("total_tokens", chunk.Usage.TotalTokens))
	}
}

func streamHeaders(provider string) map[string][]string {
	return map[string][]string{
		headerContentType:      {"text/event-stream"},
		"Cache-Control":        {"no-cache"},
		"Connection":           {"keep-alive"},
		"X-Accel-Buffering":    {"no"},
		headerSelectedProvider: {provider},
	}
}

func sourceFormatFromRequest(req *infracontext.RequestContext) adapter.Format {
	if req.SourceFormat == "" {
		return adapter.FormatOpenAI
	}
	return adapter.Format(req.SourceFormat)
}
