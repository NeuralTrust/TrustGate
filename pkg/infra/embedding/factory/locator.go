package factory

import (
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/infra/embedding/openai"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
)

const (
	OpenAIProvider = "openai"
)

type EmbeddingServiceLocator struct {
	logger     *logrus.Logger
	httpClient *fasthttp.Client
}

func NewServiceLocator(logger *logrus.Logger, httpClient *fasthttp.Client) *EmbeddingServiceLocator {
	return &EmbeddingServiceLocator{
		logger:     logger,
		httpClient: httpClient,
	}
}

func (l *EmbeddingServiceLocator) GetService(provider string) (embedding.Creator, error) {
	switch provider {
	case OpenAIProvider:
		return openai.NewOpenAIEmbeddingService(l.httpClient, l.logger), nil
	default:
		return nil, fmt.Errorf("unsupported embedding provider: %s", provider)
	}
}
