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

// ErrInvalidRequestPayload signals that the inbound body could not be decoded
// while adapting it to the target provider format. The handler maps it to a
// 400 Bad Request.
var ErrInvalidRequestPayload = errors.New("invalid request payload")

var ErrModelNotAllowed = errors.New("model not allowed")

// ProviderResponse is the backend LLM response. On the synchronous path it
// carries Body; on the streaming path it carries Stream. It is relayed to the
// client verbatim, including non-2xx backend statuses: a 4xx/5xx from the
// backend is carried here (not as a Go error) so the backend error reaches the
// client unchanged.
type ProviderResponse struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
	// Stream, when non-nil, yields SSE lines (without trailing newline) already
	// adapted to the client's source format. The consumer writes each line + "\n"
	// and is responsible for draining the sequence (which closes the backend
	// body). The second value carries mid-stream errors.
	Stream       iter.Seq2[[]byte, error]
	Usage        *adapter.CanonicalUsage
	Model        string
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
			headerSelectedProvider: {bk.Provider},
			headerContentType:      {contentTypeJSON},
		},
		Body:         respBody,
		Usage:        usage,
		Model:        model,
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
		Headers:    streamHeaders(bk.Provider),
		Stream:     stream,
	}, nil
}

// prepare resolves the provider client and transforms the request payload across
// provider formats when needed, mutating req with the resolved format metadata.
func (p *providerInvoker) prepare(
	bk *registry.Registry,
	req *infracontext.RequestContext,
) (*preparedInvocation, error) {
	client, err := p.locator.Get(bk.Provider)
	if err != nil {
		return nil, fmt.Errorf("resolve provider client: %w", err)
	}

	sourceFormat := p.resolveSourceFormat(req)
	targetFormat := adapter.ResolveTargetFormat(bk.Provider, bk.ProviderOptions)

	req.Provider = bk.Provider
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

	body = adapter.NormalizeRequestForProvider(bk.Provider, targetFormat, body)

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

	return &preparedInvocation{
		client: client,
		cfg: &providers.Config{
			Options:     bk.ProviderOptions,
			Credentials: buildCredentials(bk.Auth),
		},
		body:         body,
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

// streamHeaders returns the SSE response headers for a streamed provider
// response.
func streamHeaders(provider string) map[string][]string {
	return map[string][]string{
		headerContentType:      {"text/event-stream"},
		"Cache-Control":        {"no-cache"},
		"Connection":           {"keep-alive"},
		"X-Accel-Buffering":    {"no"},
		headerSelectedProvider: {provider},
	}
}

// resolveSourceFormat returns the client's request wire format. A non-empty
// req.SourceFormat (set from the X-Provider header) is trusted; DetectFormat is
// still run to debug-log a mismatch. Otherwise the format is auto-detected from
// the body.
func (p *providerInvoker) resolveSourceFormat(req *infracontext.RequestContext) adapter.Format {
	if req.SourceFormat != "" {
		trusted := adapter.Format(req.SourceFormat)
		if detected := adapter.DetectFormat(req.Body); detected != trusted {
			p.logger.Debug("X-Provider source format hint differs from detected format",
				slog.String("hint", string(trusted)),
				slog.String("detected", string(detected)))
		}
		return trusted
	}
	return adapter.DetectFormat(req.Body)
}

// buildCredentials maps a target's auth configuration to provider credentials.
// API key, AWS and Azure are mapped now; OAuth2 and GCP service accounts are
// deferred to the auth multi-type work (B.7).
func buildCredentials(auth *registry.TargetAuth) providers.Credentials {
	creds := providers.Credentials{}
	if auth == nil {
		return creds
	}
	switch auth.Type {
	case registry.AuthTypeAPIKey:
		if auth.APIKey != nil {
			creds.ApiKey = auth.APIKey.APIKey
		}
	case registry.AuthTypeAWS:
		if auth.AWS != nil {
			creds.AwsBedrock = &providers.AwsBedrock{
				Region:       auth.AWS.Region,
				AccessKey:    auth.AWS.AccessKeyID,
				SecretKey:    auth.AWS.SecretAccessKey,
				SessionToken: auth.AWS.SessionToken,
				UseRole:      auth.AWS.UseRole,
				RoleARN:      auth.AWS.Role,
			}
		}
	case registry.AuthTypeAzure:
		if auth.Azure != nil {
			creds.ApiKey = auth.Azure.APIKey
			creds.Azure = &providers.Azure{
				Endpoint:    auth.Azure.Endpoint,
				ApiVersion:  auth.Azure.Version,
				UseIdentity: auth.Azure.UseManagedIdentity,
			}
		}
	case registry.AuthTypeOAuth2, registry.AuthTypeGCPServiceAccount:
		// Deferred to B.7.
	}
	return creds
}
