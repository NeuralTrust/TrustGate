package proxy

import (
	"context"
	"errors"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
)

// ErrProviderNotImplemented is returned by the placeholder invoker until the
// real LLM provider adapters land (separate RUN-280 sub-issue).
var ErrProviderNotImplemented = errors.New("llm provider not implemented")

// ProviderResponse is the upstream LLM response captured on the synchronous
// (non-streaming) path.
type ProviderResponse struct {
	StatusCode int
	Headers    map[string][]string
	Body       []byte
}

// ProviderInvoker calls an upstream LLM provider for a resolved target on the
// synchronous path. The streaming variant is owned by B.5/B.6 and is not part
// of this contract yet.
//
//go:generate mockery --name=ProviderInvoker --dir=. --output=./mocks --filename=provider_invoker_mock.go --case=underscore --with-expecter
type ProviderInvoker interface {
	Invoke(ctx context.Context, target *backend.Target, req *infracontext.RequestContext) (*ProviderResponse, error)
}

var _ ProviderInvoker = (*notImplementedInvoker)(nil)

// notImplementedInvoker is the placeholder wired into the proxy plane until the
// concrete provider adapters (anthropic/openai/azure/...) are ported. It always
// reports ErrProviderNotImplemented so the data-plane skeleton stays runnable.
type notImplementedInvoker struct{}

func NewNotImplementedInvoker() ProviderInvoker {
	return &notImplementedInvoker{}
}

func (notImplementedInvoker) Invoke(
	context.Context,
	*backend.Target,
	*infracontext.RequestContext,
) (*ProviderResponse, error) {
	return nil, ErrProviderNotImplemented
}
