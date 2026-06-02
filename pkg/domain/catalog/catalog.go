package catalog

import (
	"context"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

type Provider struct {
	ID          ids.ProviderID
	Code        string
	DisplayName string
	WireFormat  string
	Source      string
	Metadata    map[string]any
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Model struct {
	ID            ids.ModelID
	ProviderID    ids.ProviderID
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
	DisableModelsExcept(ctx context.Context, providerID ids.ProviderID, source string, keepSlugs []string) error
	ListProviders(ctx context.Context) ([]Provider, error)
	ListModelsByProviderCode(ctx context.Context, providerCode string) ([]Model, error)
}
