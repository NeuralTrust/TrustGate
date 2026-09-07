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

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

const (
	headerSelectedProvider = "X-Selected-Provider"
	headerSelectedModel    = "X-Selected-Model"
	headerContentType      = "Content-Type"
	contentTypeJSON        = "application/json"

	responsesTurnIDPrefix = "resp_"
	fieldPreviousResponse = "previous_response_id"

	capabilityChat               = "chat"
	capabilityEmbeddings         = "embeddings"
	capabilityRerank             = "rerank"
	capabilityFiles              = "files"
	capabilityImages             = "images"
	capabilityAudioSpeech        = "audio_speech"
	capabilityAudioTranscription = "audio_transcription"
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

// providerCodec is the segregated view of the provider-format adapter registry
// the invoker needs: decoding and cross-format adaptation of request, response
// and stream payloads. Depending on this abstraction rather than the concrete
// registry keeps the app layer off the infra adapter implementation and makes
// the invoker testable in isolation.
type providerCodec interface {
	AdaptRequest(body []byte, source, target adapter.Format) ([]byte, error)
	DecodeResponseFor(body []byte, providerFormat adapter.Format) (*adapter.CanonicalResponse, error)
	AdaptResponse(body []byte, source, target adapter.Format) ([]byte, error)
	AdaptStreamChunk(chunk []byte, source, target adapter.Format) ([][]byte, error)
	DecodeStreamChunkFor(chunk []byte, target adapter.Format) (*adapter.CanonicalStreamChunk, error)
	EncodeStreamChunkFor(canonical *adapter.CanonicalStreamChunk, source adapter.Format) ([][]byte, error)
}

var _ ProviderInvoker = (*providerInvoker)(nil)

type providerInvoker struct {
	locator  factory.ProviderLocator
	registry providerCodec
	logger   *slog.Logger
}

func NewProviderInvoker(
	locator factory.ProviderLocator,
	registry providerCodec,
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
	capability   string
	files        providers.FilesRequest
	images       providers.ImagesRequest
	audio        providers.AudioRequest
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

	if prep.capability == capabilityFiles {
		return p.invokeFiles(ctx, bk, prep)
	}
	if prep.capability == capabilityImages {
		return p.invokeImages(ctx, bk, prep)
	}
	if isAudioCapability(prep.capability) {
		return p.invokeAudio(ctx, bk, prep)
	}

	respBody, err := p.invokeUpstream(ctx, prep)
	if err != nil {
		if be, ok := registry.IsBackendError(err); ok {
			return &ProviderResponse{
				StatusCode: be.StatusCode,
				Headers:    withSelectionHeaders(be.PassthroughHeaders(), bk, prep.sentModel),
				Body:       be.Body,
			}, nil
		}
		return nil, err
	}

	usage, model, finishReason, responseID := p.decodeResponseMeta(respBody, prep.targetFormat)

	if prep.crossFormat {
		adapted, aerr := p.adaptResponseBody(respBody, prep)
		if aerr != nil {
			p.logger.Warn("failed to adapt response, returning raw",
				slog.String("error", aerr.Error()))
		} else {
			respBody = adapted
		}
	}

	return &ProviderResponse{
		StatusCode: http.StatusOK,
		Headers: withSelectionHeaders(
			map[string][]string{headerContentType: {contentTypeJSON}},
			bk,
			prep.sentModel,
		),
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
	if prep.capability == capabilityFiles {
		return p.invokeFiles(ctx, bk, prep)
	}
	if isAudioCapability(prep.capability) {
		return p.invokeAudio(ctx, bk, prep)
	}

	body := prep.body
	// Registries speaking the OpenAI-style API need an explicit "stream": true even
	// when the source format (e.g. Gemini) does not carry it in the body.
	if prep.targetFormat.SupportsCanonicalToolCalls() {
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
				Headers:    withSelectionHeaders(be.PassthroughHeaders(), bk, prep.sentModel),
				Body:       be.Body,
			}, nil
		}
		return nil, fmt.Errorf("provider completions stream: %w", err)
	}

	stream := adaptStream(seq, p.registry, prep.sourceFormat, prep.targetFormat, p.logger, p.streamObserver(ctx, req))

	return &ProviderResponse{
		StatusCode: http.StatusOK,
		Headers:    withSelectionHeaders(streamHeaders(), bk, prep.sentModel),
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
	capability := capabilityFromRequest(req)
	targetFormat := adapter.ResolveTargetFormatForCapability(bk.Provider(), capability, sourceFormat, bk.ProviderOptions())

	req.Provider = bk.Provider()
	req.SourceFormat = string(sourceFormat)
	req.TargetFormat = string(targetFormat)

	if capability == capabilityFiles {
		return &preparedInvocation{
			client:       client,
			cfg:          filesProviderConfig(bk),
			body:         req.Body,
			sourceFormat: sourceFormat,
			targetFormat: targetFormat,
			capability:   capability,
			files:        filesRequestFromContext(req),
		}, nil
	}
	if capability == capabilityImages {
		return p.prepareImages(bk, req, client, sourceFormat, targetFormat)
	}
	if isAudioCapability(capability) {
		return p.prepareAudio(bk, req, client, sourceFormat, targetFormat, capability)
	}

	crossFormat := !adapter.ShouldPassthroughSameWireFormat(sourceFormat, targetFormat)

	body := req.Body
	if crossFormat {
		body, err = p.adaptRequestBody(req.Body, sourceFormat, targetFormat, capability)
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

	sentModel := resolveSentModel(body, req)

	return &preparedInvocation{
		client: client,
		cfg: &providers.Config{
			Options:       adapter.OpenAIProviderOptionsForTarget(bk.Provider(), targetFormat, bk.ProviderOptions()),
			Credentials:   providers.CredentialsFromTargetAuth(bk.Auth()),
			Model:         sentModel,
			DefaultModel:  req.DefaultModel,
			AllowedModels: req.AllowedModels,
		},
		body:         body,
		sentModel:    sentModel,
		sourceFormat: sourceFormat,
		targetFormat: targetFormat,
		crossFormat:  crossFormat,
		capability:   capability,
	}, nil
}

// Bedrock/Vertex strip the model from the adapted body (it travels out of band),
// so fall back to the post-routing request body and then the binding default.
func resolveSentModel(body []byte, req *infracontext.RequestContext) string {
	if m, err := adapter.ExtractModel(body); err == nil && m != "" {
		return m
	}
	if m, err := adapter.ExtractModel(req.Body); err == nil && m != "" {
		return m
	}
	return req.DefaultModel
}

func capabilityFromRequest(req *infracontext.RequestContext) string {
	switch req.ProxyCapability {
	case capabilityEmbeddings:
		return capabilityEmbeddings
	case capabilityRerank:
		return capabilityRerank
	case capabilityFiles:
		return capabilityFiles
	case capabilityImages:
		return capabilityImages
	case capabilityAudioSpeech:
		return capabilityAudioSpeech
	case capabilityAudioTranscription:
		return capabilityAudioTranscription
	default:
		return capabilityChat
	}
}

func (p *providerInvoker) adaptRequestBody(
	body []byte,
	sourceFormat, targetFormat adapter.Format,
	capability string,
) ([]byte, error) {
	switch capability {
	case capabilityEmbeddings:
		reg, ok := p.registry.(*adapter.Registry)
		if !ok {
			return nil, fmt.Errorf("embedding adaptation requires concrete adapter registry")
		}
		return adapter.AdaptEmbeddingRequest(reg, body, sourceFormat, targetFormat)
	case capabilityRerank:
		reg, ok := p.registry.(*adapter.Registry)
		if !ok {
			return nil, fmt.Errorf("rerank adaptation requires concrete adapter registry")
		}
		return adapter.AdaptRerankRequest(reg, body, sourceFormat, targetFormat)
	default:
		return p.registry.AdaptRequest(body, sourceFormat, targetFormat)
	}
}

func (p *providerInvoker) adaptResponseBody(body []byte, prep *preparedInvocation) ([]byte, error) {
	switch prep.capability {
	case capabilityEmbeddings:
		reg, ok := p.registry.(*adapter.Registry)
		if !ok {
			return nil, fmt.Errorf("embedding adaptation requires concrete adapter registry")
		}
		return adapter.AdaptEmbeddingResponse(reg, body, prep.sourceFormat, prep.targetFormat)
	case capabilityRerank:
		reg, ok := p.registry.(*adapter.Registry)
		if !ok {
			return nil, fmt.Errorf("rerank adaptation requires concrete adapter registry")
		}
		return adapter.AdaptRerankResponse(reg, body, prep.sourceFormat, prep.targetFormat)
	default:
		return p.registry.AdaptResponse(body, prep.sourceFormat, prep.targetFormat)
	}
}

func filesProviderConfig(bk *registry.Registry) *providers.Config {
	return &providers.Config{
		Options:     adapter.OpenAIProviderOptionsForTarget(bk.Provider(), adapter.FormatOpenAIFiles, bk.ProviderOptions()),
		Credentials: providers.CredentialsFromTargetAuth(bk.Auth()),
	}
}

func (p *providerInvoker) prepareAudio(
	bk *registry.Registry,
	req *infracontext.RequestContext,
	client providers.Client,
	sourceFormat, targetFormat adapter.Format,
	capability string,
) (*preparedInvocation, error) {
	body := req.Body
	contentType := req.HeaderValue(headerContentType)
	var sentModel string
	if providers.IsAudioMultipart(contentType) {
		sentModel = audioMultipartSentModel(contentType, body, req.DefaultModel)
		if err := adapter.CheckAllowedModel(sentModel, req.AllowedModels); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrModelNotAllowed, err.Error())
		}
	} else {
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
		sentModel = resolveSentModel(body, req)
	}
	audio := audioRequestFromContext(req)
	audio.Body = body
	if audio.ContentType == "" {
		audio.ContentType = contentTypeJSON
	}
	return &preparedInvocation{
		client: client,
		cfg: &providers.Config{
			Options:       adapter.OpenAIProviderOptionsForTarget(bk.Provider(), adapter.FormatOpenAIAudio, bk.ProviderOptions()),
			Credentials:   providers.CredentialsFromTargetAuth(bk.Auth()),
			Model:         sentModel,
			DefaultModel:  req.DefaultModel,
			AllowedModels: req.AllowedModels,
		},
		body:         body,
		sentModel:    sentModel,
		sourceFormat: sourceFormat,
		targetFormat: targetFormat,
		capability:   capability,
		audio:        audio,
	}, nil
}

func audioRequestFromContext(req *infracontext.RequestContext) providers.AudioRequest {
	return providers.AudioRequest{
		Method:      req.Method,
		Path:        providers.RestAfterConsumerSlug(req.Path),
		Query:       req.Query,
		ContentType: req.HeaderValue(headerContentType),
		Body:        req.Body,
	}
}

func audioMultipartSentModel(contentType string, body []byte, defaultModel string) string {
	model := providers.ExtractAudioModel(contentType, body)
	if intent, err := routingdomain.ParseModelRef(model); err == nil {
		switch {
		case intent.IsQualified(), intent.IsShortModel():
			model = intent.Model
		case intent.IsAuto(), intent.IsPool():
			model = ""
		}
	}
	if model == "" {
		return defaultModel
	}
	return model
}

func (p *providerInvoker) invokeAudio(
	ctx context.Context,
	bk *registry.Registry,
	prep *preparedInvocation,
) (*ProviderResponse, error) {
	if err := providers.ValidateAudioMethod(prep.audio.Method, prep.audio.Path); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidRequestPayload, err.Error())
	}
	result, err := invokeAudioClient(ctx, prep)
	if err != nil {
		if be, ok := registry.IsBackendError(err); ok {
			return &ProviderResponse{
				StatusCode: be.StatusCode,
				Headers:    withSelectionHeaders(be.PassthroughHeaders(), bk, prep.sentModel),
				Body:       be.Body,
			}, nil
		}
		return nil, fmt.Errorf("provider audio: %w", err)
	}
	contentType := result.ContentType
	if contentType == "" {
		contentType = contentTypeJSON
	}
	return &ProviderResponse{
		StatusCode: http.StatusOK,
		Headers: withSelectionHeaders(
			map[string][]string{headerContentType: {contentType}},
			bk,
			prep.sentModel,
		),
		Body:      result.Body,
		SentModel: prep.sentModel,
	}, nil
}

func invokeAudioClient(ctx context.Context, prep *preparedInvocation) (*providers.AudioResult, error) {
	switch prep.capability {
	case capabilityAudioSpeech:
		client, ok := prep.client.(providers.AudioSpeechClient)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrCapabilityNotSupported, capabilityAudioSpeech)
		}
		return client.AudioSpeech(ctx, prep.cfg, prep.audio)
	case capabilityAudioTranscription:
		client, ok := prep.client.(providers.AudioTranscriptionClient)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrCapabilityNotSupported, capabilityAudioTranscription)
		}
		return client.AudioTranscription(ctx, prep.cfg, prep.audio)
	default:
		return nil, fmt.Errorf("%w: %s", ErrCapabilityNotSupported, prep.capability)
	}
}

func filesRequestFromContext(req *infracontext.RequestContext) providers.FilesRequest {
	return providers.FilesRequest{
		Method:      req.Method,
		Path:        providers.RestAfterConsumerSlug(req.Path),
		Query:       req.Query,
		ContentType: req.HeaderValue(headerContentType),
		Body:        req.Body,
	}
}

func (p *providerInvoker) prepareImages(
	bk *registry.Registry,
	req *infracontext.RequestContext,
	client providers.Client,
	sourceFormat, targetFormat adapter.Format,
) (*preparedInvocation, error) {
	body := req.Body
	contentType := req.HeaderValue(headerContentType)
	var sentModel string
	if providers.IsImagesMultipart(contentType) {
		sentModel = imagesMultipartSentModel(contentType, body, req.DefaultModel)
		if err := adapter.CheckAllowedModel(sentModel, req.AllowedModels); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrModelNotAllowed, err.Error())
		}
	} else {
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
		sentModel = resolveSentModel(body, req)
	}
	images := imagesRequestFromContext(req)
	images.Body = body
	if images.ContentType == "" {
		images.ContentType = contentTypeJSON
	}
	return &preparedInvocation{
		client: client,
		cfg: &providers.Config{
			Options:       adapter.OpenAIProviderOptionsForTarget(bk.Provider(), adapter.FormatOpenAIImages, bk.ProviderOptions()),
			Credentials:   providers.CredentialsFromTargetAuth(bk.Auth()),
			Model:         sentModel,
			DefaultModel:  req.DefaultModel,
			AllowedModels: req.AllowedModels,
		},
		body:         body,
		sentModel:    sentModel,
		sourceFormat: sourceFormat,
		targetFormat: targetFormat,
		capability:   capabilityImages,
		images:       images,
	}, nil
}

func imagesRequestFromContext(req *infracontext.RequestContext) providers.ImagesRequest {
	return providers.ImagesRequest{
		Method:      req.Method,
		Path:        providers.RestAfterConsumerSlug(req.Path),
		Query:       req.Query,
		ContentType: req.HeaderValue(headerContentType),
		Body:        req.Body,
	}
}

func imagesMultipartSentModel(contentType string, body []byte, defaultModel string) string {
	model := providers.ExtractImagesModel(contentType, body)
	if intent, err := routingdomain.ParseModelRef(model); err == nil {
		switch {
		case intent.IsQualified(), intent.IsShortModel():
			model = intent.Model
		case intent.IsAuto(), intent.IsPool():
			model = ""
		}
	}
	if model == "" {
		return defaultModel
	}
	return model
}

func (p *providerInvoker) invokeFiles(
	ctx context.Context,
	bk *registry.Registry,
	prep *preparedInvocation,
) (*ProviderResponse, error) {
	filesClient, ok := prep.client.(providers.FilesClient)
	if !ok {
		return nil, fmt.Errorf("%w: files", ErrCapabilityNotSupported)
	}
	if err := providers.ValidateFilesMethod(prep.files.Method, prep.files.Path); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidRequestPayload, err.Error())
	}
	result, err := filesClient.Files(ctx, prep.cfg, prep.files)
	if err != nil {
		if be, ok := registry.IsBackendError(err); ok {
			return &ProviderResponse{
				StatusCode: be.StatusCode,
				Headers:    withSelectionHeaders(be.PassthroughHeaders(), bk, prep.sentModel),
				Body:       be.Body,
			}, nil
		}
		return nil, fmt.Errorf("provider files: %w", err)
	}
	contentType := result.ContentType
	if contentType == "" {
		contentType = contentTypeJSON
	}
	return &ProviderResponse{
		StatusCode: http.StatusOK,
		Headers: withSelectionHeaders(
			map[string][]string{headerContentType: {contentType}},
			bk,
			prep.sentModel,
		),
		Body: result.Body,
	}, nil
}

func (p *providerInvoker) invokeImages(
	ctx context.Context,
	bk *registry.Registry,
	prep *preparedInvocation,
) (*ProviderResponse, error) {
	imagesClient, ok := prep.client.(providers.ImagesClient)
	if !ok {
		return nil, fmt.Errorf("%w: images", ErrCapabilityNotSupported)
	}
	if err := providers.ValidateImagesMethod(prep.images.Method, prep.images.Path); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidRequestPayload, err.Error())
	}
	result, err := imagesClient.Images(ctx, prep.cfg, prep.images)
	if err != nil {
		if be, ok := registry.IsBackendError(err); ok {
			return &ProviderResponse{
				StatusCode: be.StatusCode,
				Headers:    withSelectionHeaders(be.PassthroughHeaders(), bk, prep.sentModel),
				Body:       be.Body,
			}, nil
		}
		return nil, fmt.Errorf("provider images: %w", err)
	}
	contentType := result.ContentType
	if contentType == "" {
		contentType = contentTypeJSON
	}
	return &ProviderResponse{
		StatusCode: http.StatusOK,
		Headers: withSelectionHeaders(
			map[string][]string{headerContentType: {contentType}},
			bk,
			prep.sentModel,
		),
		Body:      result.Body,
		SentModel: prep.sentModel,
	}, nil
}

func (p *providerInvoker) invokeUpstream(ctx context.Context, prep *preparedInvocation) ([]byte, error) {
	switch prep.capability {
	case capabilityEmbeddings:
		embedder, ok := prep.client.(providers.EmbeddingsClient)
		if !ok {
			return nil, fmt.Errorf("%w: embeddings", ErrCapabilityNotSupported)
		}
		respBody, err := embedder.Embeddings(ctx, prep.cfg, prep.body)
		if err != nil {
			return nil, fmt.Errorf("provider embeddings: %w", err)
		}
		return respBody, nil
	case capabilityRerank:
		reranker, ok := prep.client.(providers.RerankClient)
		if !ok {
			return nil, fmt.Errorf("%w: rerank", ErrCapabilityNotSupported)
		}
		respBody, err := reranker.Rerank(ctx, prep.cfg, prep.body)
		if err != nil {
			return nil, fmt.Errorf("provider rerank: %w", err)
		}
		return respBody, nil
	default:
		respBody, err := prep.client.Completions(ctx, prep.cfg, prep.body)
		if err != nil {
			return nil, fmt.Errorf("provider completions: %w", err)
		}
		return respBody, nil
	}
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

func (p *providerInvoker) streamObserver(ctx context.Context, req *infracontext.RequestContext) func(*adapter.CanonicalStreamChunk) {
	requestTrace := trace.FromContext(ctx)
	return func(chunk *adapter.CanonicalStreamChunk) {
		if chunk == nil {
			return
		}
		if requestTrace != nil {
			requestTrace.ObserveLLMResult(chunk.Model, chunk.FinishReason)
			requestTrace.ObserveLLMTurnID(chunk.ID)
		}
		if chunk.Usage == nil {
			return
		}
		if req != nil {
			if req.Metadata == nil {
				req.Metadata = map[string]interface{}{}
			}
			prev, _ := req.Metadata[adapter.MetadataUsageKey].(*adapter.CanonicalUsage)
			req.Metadata[adapter.MetadataUsageKey] = adapter.MergeUsage(prev, chunk.Usage)
		}
		if requestTrace != nil {
			requestTrace.ObserveLLMUsage(chunk.Usage)
		}
		p.logger.Debug("stream usage observed",
			slog.Int("input_tokens", chunk.Usage.InputTokens),
			slog.Int("output_tokens", chunk.Usage.OutputTokens),
			slog.Int("total_tokens", chunk.Usage.TotalTokens))
	}
}

func streamHeaders() map[string][]string {
	return map[string][]string{
		headerContentType:   {"text/event-stream"},
		"Cache-Control":     {"no-cache"},
		"Connection":        {"keep-alive"},
		"X-Accel-Buffering": {"no"},
	}
}

func withSelectionHeaders(
	headers map[string][]string,
	bk *registry.Registry,
	sentModel string,
) map[string][]string {
	// No capacity hint: len(headers)+N trips CodeQL's allocation-overflow check
	// and HTTP header maps are tiny, so the hint buys nothing.
	out := make(map[string][]string)
	for name, values := range headers {
		out[name] = values
	}
	if provider := bk.Provider(); provider != "" {
		out[headerSelectedProvider] = []string{provider}
	}
	if sentModel != "" {
		out[headerSelectedModel] = []string{sentModel}
	}
	return out
}

func sourceFormatFromRequest(req *infracontext.RequestContext) adapter.Format {
	if req.SourceFormat == "" {
		return adapter.FormatOpenAI
	}
	return adapter.Format(req.SourceFormat)
}
