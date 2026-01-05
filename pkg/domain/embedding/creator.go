package embedding

import (
	"context"
)

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=embedding_creator_mock.go --case=underscore --with-expecter

type Creator interface {
	Generate(ctx context.Context, text, model string, credentials *Config) (*Embedding, error)
}
