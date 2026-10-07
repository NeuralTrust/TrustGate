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

package proxy_test

import (
	"context"
	"testing"

	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func (fx storeFixture) storeModelsInput() appproxy.StoreModelsInput {
	return appproxy.StoreModelsInput{Links: fx.data.StoreLinks(fx.authID), Data: fx.data}
}

func newStoreModels() appproxy.StoreModels {
	return appproxy.NewStoreModels(approuting.NewResolver(), workedCatalog)
}

type countingCatalog struct {
	storeCatalog
	calls map[string]int
}

func (c *countingCatalog) ListModels(ctx context.Context, provider string) ([]catalogdomain.Model, error) {
	c.calls[provider]++
	return c.storeCatalog.ListModels(ctx, provider)
}

func TestStoreModels_ListIsTheUnionAfterSubstitution(t *testing.T) {
	cases := []struct {
		name   string
		grants []storeGrant
		want   []string
	}{
		{name: "union with substitution", grants: []storeGrant{grantA, grantB, grantC, grantD},
			want: []string{"gpt6", "opus-4.8", "opus-5.5"}},
		{name: "union without a user link", grants: []storeGrant{grantA, grantB, grantC},
			want: []string{"gpt-4.1", "gpt6", "opus-4.8", "opus-5.5"}},
		{name: "no links", want: []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list, err := newStoreModels().List(context.Background(), newStoreFixture(tc.grants...).storeModelsInput())
			require.NoError(t, err)
			assert.Equal(t, "list", list.Object)
			require.NotNil(t, list.Data)
			got := make([]string, 0, len(list.Data))
			for _, card := range list.Data {
				got = append(got, card.ID)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestStoreModels_GetFindsOnlyListedModels(t *testing.T) {
	in := newStoreFixture(grantA, grantB, grantC, grantD).storeModelsInput()
	card, err := newStoreModels().Get(context.Background(), in, "opus-5.5")
	require.NoError(t, err)
	assert.Equal(t, appproxy.ModelCard{ID: "opus-5.5", Object: "model", OwnedBy: "anthropic"}, *card)
	for _, id := range []string{"gpt-4.1", "deepseek-chat"} {
		_, err := newStoreModels().Get(context.Background(), in, id)
		require.ErrorIs(t, err, appproxy.ErrModelNotFound, id)
	}
}

func TestStoreModels_QueriesEachProviderListingOncePerRequest(t *testing.T) {
	openAnthropic := storeGrant{name: "E", level: levelGroup, priority: 1, regs: []storeRegistry{{provider: "anthropic"}}}
	globAnthropic := storeGrant{name: "G", level: levelAll, priority: 1, regs: []storeRegistry{{provider: "anthropic", allowed: []string{"opus-*"}}}}
	in := newStoreFixture(grantA, grantB, openAnthropic, globAnthropic).storeModelsInput()
	catalog := &countingCatalog{storeCatalog: workedCatalog, calls: map[string]int{}}
	models := appproxy.NewStoreModels(approuting.NewResolver(), catalog)

	list, err := models.List(context.Background(), in)
	require.NoError(t, err)
	assert.Len(t, list.Data, 4)
	assert.Equal(t, map[string]int{"openai": 1, "anthropic": 1}, catalog.calls)

	catalog.calls = map[string]int{}
	card, err := models.Get(context.Background(), in, "gpt6")
	require.NoError(t, err)
	assert.Equal(t, "openai", card.OwnedBy)
	assert.Equal(t, map[string]int{"openai": 1}, catalog.calls)
}
