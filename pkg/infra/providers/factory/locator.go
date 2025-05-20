package factory

import (
	"fmt"
	"os"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/gemini"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/openai"
	"github.com/valyala/fasthttp"
)

const (
	ProviderOpenAI = "openai"
	ProviderGemini = "gemini"
)


//go:generate mockery --name=ProviderLocator --dir=. --output=./mocks --filename=provider_locator_mock.go --case=underscore --with-expecter

type ProviderLocator interface {
	Get(provider string) (providers.Client, error)
}
type providerLocator struct {
	httpClient *fasthttp.Client
	googleAPIKey string
}

func NewProviderLocator(httpClient *fasthttp.Client) ProviderLocator {
	return &providerLocator{
		httpClient: httpClient,
		googleAPIKey: os.Getenv("GOOGLE_API_KEY"),
	}
}

func (f *providerLocator) Get(provider string) (providers.Client, error) {
	switch provider {
	case ProviderOpenAI:
		return openai.NewOpenaiClient(f.httpClient), nil
	case ProviderGemini:
		return gemini.NewGeminiClient(f.googleAPIKey), nil
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}
