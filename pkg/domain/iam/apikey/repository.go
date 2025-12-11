package apikey

import (
	"context"

	"github.com/google/uuid"
)

//go:generate mockery --name=Repository --dir=. --output=./mocks --filename=api_key_repo_mock.go --case=underscore --with-expecter
type Repository interface {
	GetByKey(ctx context.Context, key string) (*APIKey, error)
	GetByID(ctx context.Context, id uuid.UUID) (*APIKey, error)
	Get(ctx context.Context, id string) (*APIKey, error)
	ListWithSubject(ctx context.Context, subjectID uuid.UUID) ([]APIKey, error)
	Create(ctx context.Context, apiKey *APIKey) error
	Update(ctx context.Context, apiKey *APIKey) error
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteWithSubject(ctx context.Context, id, subjectID uuid.UUID) error
}
