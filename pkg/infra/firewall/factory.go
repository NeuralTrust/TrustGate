package firewall

import (
	"fmt"
	"strings"
)

const (
	ProviderNeuralTrust = "neuraltrust"
	ProviderOpenAI      = "openai"
)

//go:generate mockery --name=ClientFactory --dir=. --output=./mocks --filename=client_factory_mock.go --case=underscore --with-expecter
type ClientFactory interface {
	Get(provider string) (Client, error)
}

type clientFactory struct {
	clients           map[string]Client
	neuralTrustClient Client
}

func NewClientFactory(neural Client, openai Client) ClientFactory {
	clients := make(map[string]Client)

	if neural != nil {
		clients[ProviderNeuralTrust] = neural
	}
	if openai != nil {
		clients[ProviderOpenAI] = openai
	}

	return &clientFactory{
		clients:           clients,
		neuralTrustClient: neural,
	}
}

func (f *clientFactory) Get(provider string) (Client, error) {
	name := strings.ToLower(strings.TrimSpace(provider))
	if name == "" {
		if f.neuralTrustClient == nil {
			return nil, fmt.Errorf("neuraltrust firewall client not configured")
		}
		return f.neuralTrustClient, nil
	}

	if client, ok := f.clients[name]; ok {
		return client, nil
	}

	return nil, fmt.Errorf("unknown firewall provider: %s", provider)
}
