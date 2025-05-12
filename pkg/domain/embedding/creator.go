package embedding

import (
	"context"
)

type Creator interface {
	Generate(ctx context.Context, text, model string, credentials *Config) (*Embedding, error)
}
