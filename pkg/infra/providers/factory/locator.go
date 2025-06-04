package factory

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/anthropic"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/gemini"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/openai"
	"github.com/valyala/fasthttp"
)

const (
	ProviderOpenAI    = "openai"
	ProviderGemini    = "gemini"
	ProviderAnthropic = "anthropic"
)

//go:generate mockery --name=ProviderLocator --dir=. --output=./mocks --filename=provider_locator_mock.go --case=underscore --with-expecter

type ProviderLocator interface {
	Get(provider string) (providers.Client, error)
}
type providerLocator struct {
	httpClient *fasthttp.Client
}

func NewProviderLocator(httpClient *fasthttp.Client) ProviderLocator {
	return &providerLocator{
		httpClient: httpClient,
	}
}

func (f *providerLocator) Get(provider string) (providers.Client, error) {
	switch provider {
	case ProviderOpenAI:
		return openai.NewOpenaiClient(), nil
	case ProviderGemini:
		return gemini.NewGeminiClient(), nil
	case ProviderAnthropic:
		return anthropic.NewAnthropicClient(), nil
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}
