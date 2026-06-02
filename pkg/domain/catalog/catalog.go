package catalog

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Provider struct {
	ID          uuid.UUID
	Code        string
	DisplayName string
	WireFormat  string
	Source      string
	Metadata    map[string]any
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Model struct {
	ID            uuid.UUID
	ProviderID    uuid.UUID
	Slug          string
	ExternalID    string
	DisplayName   string
	ContextWindow int
	MaxOutput     int
	InputPrice    string
	OutputPrice   string
	Capabilities  map[string]any
	Enabled       bool
	Source        string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type Repository interface {
	UpsertProvider(ctx context.Context, p *Provider) error
	UpsertModel(ctx context.Context, m *Model) error
	DisableModelsExcept(ctx context.Context, providerID uuid.UUID, source string, keepSlugs []string) error
	ListProviders(ctx context.Context) ([]Provider, error)
	ListModelsByProviderCode(ctx context.Context, providerCode string) ([]Model, error)
}
