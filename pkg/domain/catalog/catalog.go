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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
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
	FindModel(ctx context.Context, providerCode, slug string) (*Model, error)
}
