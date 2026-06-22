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
	"io"
	"log/slog"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type priceRepo struct {
	*fakeRepo
	model *domain.Model
	err   error
	calls int
}

func (p *priceRepo) FindModel(_ context.Context, _ string, _ string) (*domain.Model, error) {
	p.calls++
	return p.model, p.err
}

func newPricingResolver(repo domain.Repository) PricingResolver {
	mgr := cache.NewTTLMapManager(cache.CatalogModelCacheTTL)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewPricingResolver(repo, mgr, logger)
}

func TestPricingResolver_ComputesPriceAndCachesLookup(t *testing.T) {
	repo := &priceRepo{
		fakeRepo: newFakeRepo(),
		model: &domain.Model{
			DisplayName: "GPT-4o",
			InputPrice:  "0.0000025",
			OutputPrice: "0.00001",
		},
	}
	resolver := newPricingResolver(repo)

	first := resolver.Resolve(context.Background(), "openai", "gpt-4o")
	require.True(t, first.Found)
	assert.Equal(t, "GPT-4o", first.ModelLabel)
	assert.InDelta(t, 0.0000025, first.InputPrice, 1e-12)
	assert.InDelta(t, 0.00001, first.OutputPrice, 1e-12)

	second := resolver.Resolve(context.Background(), "openai", "gpt-4o")
	assert.Equal(t, first, second)
	assert.Equal(t, 1, repo.calls, "second resolve must be served from cache")
}

func TestPricingResolver_CachesNegativeLookup(t *testing.T) {
	repo := &priceRepo{fakeRepo: newFakeRepo(), err: commonerrors.ErrNotFound}
	resolver := newPricingResolver(repo)

	first := resolver.Resolve(context.Background(), "openai", "unknown")
	assert.False(t, first.Found)

	second := resolver.Resolve(context.Background(), "openai", "unknown")
	assert.False(t, second.Found)
	assert.Equal(t, 1, repo.calls, "negative lookups must be cached to keep the hot path off the DB")
}

func TestPricingResolver_EmptyKeySkipsLookup(t *testing.T) {
	repo := &priceRepo{fakeRepo: newFakeRepo()}
	resolver := newPricingResolver(repo)

	assert.False(t, resolver.Resolve(context.Background(), "", "gpt-4o").Found)
	assert.False(t, resolver.Resolve(context.Background(), "openai", "").Found)
	assert.Equal(t, 0, repo.calls)
}

func TestParsePrice(t *testing.T) {
	assert.InDelta(t, 0.0000025, parsePrice("0.0000025"), 1e-12)
	assert.Equal(t, 0.0, parsePrice(""))
	assert.Equal(t, 0.0, parsePrice("not-a-number"))
}
