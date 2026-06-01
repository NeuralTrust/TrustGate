package proxy

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net/http"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/adapter"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/providers/factory"
)

const (
	headerSelectedProvider = "X-Selected-Provider"
	headerContentType      = "Content-Type"
	contentTypeJSON        = "application/json"
)

// ErrInvalidRequestPayload signals that the inbound body could not be decoded
// while adapting it to the target provider format. The handler maps it to a
// 400 Bad Request.
var ErrInvalidRequestPayload = errors.New("invalid request payload")

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
	Stream iter.Seq2[[]byte, error]
}

//go:generate mockery --name=ProviderInvoker --dir=. --output=./mocks --filename=provider_invoker_mock.go --case=underscore --with-expecter
type ProviderInvoker interface {
	Invoke(ctx context.Context, bk *backend.Backend, req *infracontext.RequestContext) (*ProviderResponse, error)
	// InvokeStream performs the streaming invocation. A pre-stream non-2xx
	// backend response is returned as a verbatim *ProviderResponse (Body set,
	// Stream nil); a successful call returns a *ProviderResponse with Stream set.
	InvokeStream(ctx context.Context, bk *backend.Backend, req *infracontext.RequestContext) (*ProviderResponse, error)
}

var _ ProviderInvoker = (*providerInvoker)(nil)

// providerInvoker resolves the concrete LLM provider client for a backend,
// transforms the request payload across provider formats when needed, invokes
// the backend, and adapts the response back to the client's source format.
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
	bk *backend.Backend,
	req *infracontext.RequestContext,
) (*ProviderResponse, error) {
	prep, err := p.prepare(bk, req)
	if err != nil {
		return nil, err
	}

	respBody, err := prep.client.Completions(ctx, prep.cfg, prep.body)
	if err != nil {
		if be, ok := backend.IsBackendError(err); ok {
			return &ProviderResponse{
				StatusCode: be.StatusCode,
				Headers:    be.PassthroughHeaders(),
				Body:       be.Body,
			}, nil
		}
		return nil, fmt.Errorf("provider completions: %w", err)
	}

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
		Body: respBody,
	}, nil
}

func (p *providerInvoker) InvokeStream(
	ctx context.Context,
	bk *backend.Backend,
	req *infracontext.RequestContext,
) (*ProviderResponse, error) {
	prep, err := p.prepare(bk, req)
	if err != nil {
		return nil, err
	}

	body := prep.body
	// Backends speaking the OpenAI-style API need an explicit "stream": true even
	// when the source format (e.g. Gemini) does not carry it in the body.
	if adapter.IsSameWireFormat(prep.targetFormat, adapter.FormatOpenAI) ||
		prep.targetFormat == adapter.FormatOpenAIResponses ||
		prep.targetFormat == adapter.FormatAnthropic ||
		prep.targetFormat == adapter.FormatMistral {
		body = injectStreamTrue(body)
	}

	seq, err := prep.client.CompletionsStream(ctx, prep.cfg, body)
	if err != nil {
		if be, ok := backend.IsBackendError(err); ok {
			return &ProviderResponse{
				StatusCode: be.StatusCode,
				Headers:    be.PassthroughHeaders(),
				Body:       be.Body,
			}, nil
		}
		return nil, fmt.Errorf("provider completions stream: %w", err)
	}

	stream := adaptStream(seq, p.registry, prep.sourceFormat, prep.targetFormat, p.logger, p.usageObserver(req))

	return &ProviderResponse{
		StatusCode: http.StatusOK,
		Headers:    streamHeaders(bk.Provider),
		Stream:     stream,
	}, nil
}

// prepare resolves the provider client and transforms the request payload across
// provider formats when needed, mutating req with the resolved format metadata.
func (p *providerInvoker) prepare(
	bk *backend.Backend,
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

	// ValidateModel is a near no-op until the backend carries an allow-list /
	// default model; failures are non-fatal (proceed without model override).
	if normalized, _, verr := adapter.ValidateModel(body, nil, ""); verr != nil {
		p.logger.Warn("model validation failed, proceeding without override",
			slog.String("error", verr.Error()))
	} else {
		body = normalized
	}

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

// usageObserver returns a callback that records the latest canonical usage onto
// req.Metadata["usage"] and debug-logs it. This is the chunk-level metric hook.
func (p *providerInvoker) usageObserver(req *infracontext.RequestContext) func(*adapter.CanonicalUsage) {
	return func(u *adapter.CanonicalUsage) {
		if u == nil {
			return
		}
		if req.Metadata == nil {
			req.Metadata = make(map[string]interface{})
		}
		req.Metadata[adapter.MetadataUsageKey] = u
		p.logger.Debug("stream usage observed",
			slog.Int("input_tokens", u.InputTokens),
			slog.Int("output_tokens", u.OutputTokens),
			slog.Int("total_tokens", u.TotalTokens))
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
func buildCredentials(auth *backend.TargetAuth) providers.Credentials {
	creds := providers.Credentials{}
	if auth == nil {
		return creds
	}
	switch auth.Type {
	case backend.AuthTypeAPIKey:
		if auth.APIKey != nil {
			creds.ApiKey = auth.APIKey.APIKey
		}
	case backend.AuthTypeAWS:
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
	case backend.AuthTypeAzure:
		if auth.Azure != nil {
			creds.Azure = &providers.Azure{
				Endpoint:    auth.Azure.Endpoint,
				ApiVersion:  auth.Azure.Version,
				UseIdentity: auth.Azure.UseManagedIdentity,
			}
		}
	case backend.AuthTypeOAuth2, backend.AuthTypeGCPServiceAccount:
		// Deferred to B.7.
	}
	return creds
}
