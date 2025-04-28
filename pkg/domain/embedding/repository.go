package embedding

import (
	"context"
)

type Repository interface {
	Store(ctx context.Context, targetID string, embeddingData *Embedding) error
	GetByTargetID(ctx context.Context, targetID string) (*Embedding, error)
}
