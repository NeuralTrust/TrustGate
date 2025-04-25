package embedding

import (
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
)

type Creator interface {
	Generate(ctx context.Context, text, model string, credentials upstream.EmbeddingConfig) (*Embedding, error)
}
