package factory

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/openai"
	"github.com/NeuralTrust/TrustGate/pkg/infra/httpx"
	"github.com/sirupsen/logrus"
)

const (
	OpenAIProvider = "openai"
)

//go:generate mockery --name=EmbeddingServiceLocator --dir=. --output=./mocks --filename=embedding_locator_mock.go --case=underscore --with-expecter
type EmbeddingServiceLocator interface {
	GetService(provider string) (embedding.Creator, error)
}

type embeddingServiceLocator struct {
	logger     *logrus.Logger
	httpClient *httpx.FastHTTPClient
}

func NewServiceLocator(logger *logrus.Logger, httpClient *httpx.FastHTTPClient) EmbeddingServiceLocator {
	return &embeddingServiceLocator{
		logger:     logger,
		httpClient: httpClient,
	}
}

func (l *embeddingServiceLocator) GetService(provider string) (embedding.Creator, error) {
	switch provider {
	case OpenAIProvider:
		return openai.NewOpenAIEmbeddingService(l.httpClient.Underlying(), l.logger), nil
	default:
		return nil, fmt.Errorf("unsupported embedding provider: %s", provider)
	}
}
