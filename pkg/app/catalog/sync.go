// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package catalog

import (
	"context"
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/infra/bootlog"
	"github.com/NeuralTrust/TrustGate/pkg/infra/catalog/modelsdev"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

// releaseDateLayout is the "YYYY-MM-DD" format models.dev publishes for release_date.
const releaseDateLayout = "2006-01-02"

// parseReleaseDate turns a models.dev release_date string into a date, returning
// nil for empty or unparseable values so the model simply sorts last.
func parseReleaseDate(raw string) *time.Time {
	if raw == "" {
		return nil
	}
	t, err := time.Parse(releaseDateLayout, raw)
	if err != nil {
		return nil
	}
	return &t
}

const sourceModelsDev = "models.dev"
const sourceManualSeed = "seed"

type seedProvider struct {
	code        string
	displayName string
	wireFormat  string
}

type seedModel struct {
	slug         string
	externalID   string
	displayName  string
	capabilities map[string]any
}

var seedProviders = []seedProvider{
	{providers.ProviderOpenAI, "OpenAI", "openai"},
	{providers.ProviderOpenAICompatible, "OpenAI Compatible", "openai"},
	{providers.ProviderGoogle, "Google AI Studio", "google"},
	{providers.ProviderVertex, "Google Vertex AI", "google"},
	{providers.ProviderAnthropic, "Anthropic", "anthropic"},
	{providers.ProviderBedrock, "AWS Bedrock", "anthropic"},
	{providers.ProviderAzure, "Azure OpenAI", "openai"},
	{providers.ProviderMistral, "Mistral", "openai"},
	{providers.ProviderGroq, "Groq", "openai"},
	{providers.ProviderDeepSeek, "DeepSeek", "openai"},
	{providers.ProviderXAI, "xAI", "openai"},
	{providers.ProviderCerebras, "Cerebras", "openai"},
	{providers.ProviderOpenRouter, "OpenRouter", "openai"},
	{providers.ProviderCohere, "Cohere", "cohere"},
}

var cohereSeedModels = []seedModel{
	{
		slug:        "command-r-plus",
		externalID:  "command-r-plus",
		displayName: "Command R+",
		capabilities: map[string]any{
			"chat":   true,
			"rerank": true,
		},
	},
	{
		slug:        "embed-english-v3.0",
		externalID:  "embed-english-v3.0",
		displayName: "Embed English v3.0",
		capabilities: map[string]any{
			"embed": true,
		},
	},
	{
		slug:        "rerank-english-v3.0",
		externalID:  "rerank-english-v3.0",
		displayName: "Rerank English v3.0",
		capabilities: map[string]any{
			"rerank": true,
		},
	},
}

// modelsDevProviderToCode maps models.dev provider keys to the gateway provider
// codes. Only mapped providers are imported; everything else is ignored.
var modelsDevProviderToCode = map[string]string{
	"openai":         providers.ProviderOpenAI,
	"google":         providers.ProviderGoogle,
	"google-vertex":  providers.ProviderVertex,
	"anthropic":      providers.ProviderAnthropic,
	"amazon-bedrock": providers.ProviderBedrock,
	"azure":          providers.ProviderAzure,
	"mistral":        providers.ProviderMistral,
	"groq":           providers.ProviderGroq,
	"deepseek":       providers.ProviderDeepSeek,
	"xai":            providers.ProviderXAI,
	"cerebras":       providers.ProviderCerebras,
	"openrouter":     providers.ProviderOpenRouter,
	"cohere":         providers.ProviderCohere,
}

//go:generate mockery --name=Syncer --dir=. --output=./mocks --filename=catalog_syncer_mock.go --case=underscore --with-expecter
type Syncer interface {
	Sync(ctx context.Context) error
}

var _ Syncer = (*syncer)(nil)

type syncer struct {
	repo     domain.Repository
	client   *modelsdev.Client
	logger   *slog.Logger
	signaler configsyncport.SnapshotSignaler
}

func NewSyncer(repo domain.Repository, client *modelsdev.Client, logger *slog.Logger, signaler configsyncport.SnapshotSignaler) Syncer {
	return &syncer{repo: repo, client: client, logger: logger, signaler: signaler}
}

func (s *syncer) Sync(ctx context.Context) error {
	if err := s.seedProviders(ctx); err != nil {
		return err
	}

	codeToProvider, err := s.providerIndex(ctx)
	if err != nil {
		return err
	}

	if err := s.seedManualModels(ctx, codeToProvider); err != nil {
		return err
	}

	models, err := s.client.ListModels(ctx)
	if err != nil {
		return err
	}

	keepByProvider := make(map[string][]string)
	for _, m := range models {
		code, ok := modelsDevProviderToCode[m.ProviderCode]
		if !ok {
			continue
		}
		provider, ok := codeToProvider[code]
		if !ok {
			continue
		}
		entity := &domain.Model{
			ProviderID:       provider.ID,
			Slug:             m.Slug,
			ExternalID:       m.ExternalID,
			DisplayName:      m.DisplayName,
			ContextWindow:    m.ContextWindow,
			MaxOutput:        m.MaxOutput,
			InputPrice:       m.InputPrice,
			OutputPrice:      m.OutputPrice,
			ReleaseDate:      parseReleaseDate(m.ReleaseDate),
			InputModalities:  m.InputModalities,
			OutputModalities: m.OutputModalities,
			Enabled:          true,
			Source:           sourceModelsDev,
		}
		if err := s.repo.UpsertModel(ctx, entity); err != nil {
			return err
		}
		keepByProvider[code] = append(keepByProvider[code], m.Slug)
	}

	for code, provider := range codeToProvider {
		if err := s.repo.DisableModelsExcept(ctx, provider.ID, sourceModelsDev, keepByProvider[code]); err != nil {
			return err
		}
	}

	s.logger.Info(bootlog.CatalogSyncCompleted,
		slog.Int("providers", len(seedProviders)),
		slog.Int("models", len(models)))
	if s.signaler != nil {
		s.signaler.Signal(ctx)
	}
	return nil
}

func (s *syncer) seedProviders(ctx context.Context) error {
	for _, p := range seedProviders {
		entity := &domain.Provider{
			Code:        p.code,
			DisplayName: p.displayName,
			WireFormat:  p.wireFormat,
			Source:      "seed",
		}
		if err := s.repo.UpsertProvider(ctx, entity); err != nil {
			return err
		}
	}
	return nil
}

func (s *syncer) seedManualModels(ctx context.Context, codeToProvider map[string]domain.Provider) error {
	provider, ok := codeToProvider[providers.ProviderCohere]
	if !ok {
		return nil
	}
	for _, m := range cohereSeedModels {
		entity := &domain.Model{
			ProviderID:    provider.ID,
			Slug:          m.slug,
			ExternalID:    m.externalID,
			DisplayName:   m.displayName,
			Capabilities:  m.capabilities,
			Enabled:       true,
			Source:        sourceManualSeed,
		}
		if err := s.repo.UpsertModel(ctx, entity); err != nil {
			return err
		}
	}
	return nil
}

func (s *syncer) providerIndex(ctx context.Context) (map[string]domain.Provider, error) {
	stored, err := s.repo.ListProviders(ctx)
	if err != nil {
		return nil, err
	}
	index := make(map[string]domain.Provider, len(stored))
	for _, p := range stored {
		index[p.Code] = p
	}
	return index, nil
}
