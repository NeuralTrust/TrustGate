package factory

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/anthropic"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/azure"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/bedrock"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/google"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/mistral"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/openai"
)

// Provider name constants — aliased from the providers package so existing
// callers that import factory.ProviderX continue to compile.
const (
	ProviderOpenAI    = providers.ProviderOpenAI
	ProviderGoogle    = providers.ProviderGoogle
	ProviderAnthropic = providers.ProviderAnthropic
	ProviderBedrock   = providers.ProviderBedrock
	ProviderAzure     = providers.ProviderAzure
	ProviderMistral   = providers.ProviderMistral
)

//go:generate mockery --name=ProviderLocator --dir=. --output=./mocks --filename=provider_locator_mock.go --case=underscore --with-expecter

type ProviderLocator interface {
	Get(provider string) (providers.Client, error)
}
type providerLocator struct{}

func NewProviderLocator() ProviderLocator {
	return &providerLocator{}
}

func (f *providerLocator) Get(provider string) (providers.Client, error) {
	switch provider {
	case ProviderOpenAI:
		return openai.NewOpenaiClient(), nil
	case ProviderGoogle:
		return google.NewGoogleClient(), nil
	case ProviderAnthropic:
		return anthropic.NewAnthropicClient(), nil
	case ProviderBedrock:
		return bedrock.NewBedrockClient(), nil
	case ProviderAzure:
		return azure.NewAzureClient(), nil
	case ProviderMistral:
		return mistral.NewMistralClient(), nil
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}
