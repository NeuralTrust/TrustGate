package embedding

import (
	"context"
)

//go:generate mockery --name=EmbeddingRepository --dir=. --output=./mocks --filename=embedding_repository_mock.go --case=underscore --with-expecter

type Repository interface {
	Count(ctx context.Context, index, keyQuery string) (int, error)
	Store(ctx context.Context, targetID string, embeddingData *Embedding, key string) error
	GetByTargetID(ctx context.Context, targetID string) (*Embedding, error)
	StoreWithHMSet(ctx context.Context, index string, key string, gatewayID string, embedding *Embedding, data []byte) error
	Search(ctx context.Context, index string, query string, embedding *Embedding) ([]SearchResult, error)
}
