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
	"errors"
	"testing"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	catalogmocks "github.com/NeuralTrust/TrustGate/pkg/app/catalog/mocks"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	domainconsumer "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	"github.com/stretchr/testify/mock"
)

func TestListModels_AllowList(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, openai)
	rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{
		openai.ID: {Allowed: []string{"gpt-4o-mini", "text-embedding-3-small"}},
	}

	list := listModels(t, rc, catalogmocks.NewService(t))
	assertModelIDs(t, list, "gpt-4o-mini", "text-embedding-3-small")
	assertOwnedBy(t, list, "gpt-4o-mini", "openai")
}

func TestListModels_FiltersIncapableAllowListEntries(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	anthropic := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, anthropic)
	rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{
		anthropic.ID: {Allowed: []string{"claude-sonnet-4", "text-embedding-3-small", "rerank-english-v3.0"}},
	}

	list := listModels(t, rc, catalogmocks.NewService(t))
	assertModelIDs(t, list, "claude-sonnet-4")
}

func TestListModels_OpenCatalogExpandsEnabledModels(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, openai)

	cat := catalogmocks.NewService(t)
	cat.EXPECT().ListModels(mock.Anything, "openai").Return([]catalogdomain.Model{
		{Slug: "gpt-4o", Capabilities: map[string]any{"chat": true}},
		{Slug: "text-embedding-3-small", Capabilities: map[string]any{"embed": true}},
		{Slug: "rerank-english-v3.0", Capabilities: map[string]any{"rerank": true}},
	}, nil).Once()

	list := listModels(t, rc, cat)
	assertModelIDs(t, list, "gpt-4o", "text-embedding-3-small")
}

func TestListModels_OpenCatalogFiltersByProviderCapability(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	anthropic := backendFor(gatewayID, "anthropic")
	rc := routableConsumerWith(gatewayID, anthropic)

	cat := catalogmocks.NewService(t)
	cat.EXPECT().ListModels(mock.Anything, "anthropic").Return([]catalogdomain.Model{
		{Slug: "claude-sonnet-4"},
		{Slug: "text-embedding-3-small"},
	}, nil).Once()

	list := listModels(t, rc, cat)
	assertModelIDs(t, list, "claude-sonnet-4")
}

func TestListModels_UnionDedupesSharedSlugs(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	azure := backendFor(gatewayID, "azure")
	rc := routableConsumerWith(gatewayID, openai, azure)
	rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{
		openai.ID: {Allowed: []string{"gpt-4o"}},
		azure.ID:  {Allowed: []string{"gpt-4o", "gpt-4o-mini"}},
	}

	list := listModels(t, rc, catalogmocks.NewService(t))
	assertModelIDs(t, list, "gpt-4o", "gpt-4o-mini")
	assertOwnedBy(t, list, "gpt-4o", "openai")
	assertOwnedBy(t, list, "gpt-4o-mini", "azure")
}

func TestListModels_PoolMemberModelsAreIncluded(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, openai)
	rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{
		openai.ID: {Allowed: []string{"gpt-4o-mini"}},
	}
	rc.Consumer.LBConfig.Enabled = true
	rc.Consumer.LBConfig.Members = []domainconsumer.LBPoolMember{
		{RegistryID: openai.ID, Models: []string{"gpt-4o-mini", "o1-mini"}},
	}

	list := listModels(t, rc, catalogmocks.NewService(t))
	assertModelIDs(t, list, "gpt-4o-mini", "o1-mini")
}

func TestListModels_RoleBasedAllowList(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	role := &roledomain.Role{
		ID:          ids.New[ids.RoleKind](),
		GatewayID:   gatewayID,
		Name:        "analyst",
		RegistryIDs: []ids.RegistryID{openai.ID},
		ModelPolicies: roledomain.ModelPolicies{
			openai.ID: {Allowed: []string{"gpt-5"}},
		},
	}
	rc := &appconsumer.RoutableConsumer{
		Consumer: &domainconsumer.Consumer{
			ID:          ids.New[ids.ConsumerKind](),
			GatewayID:   gatewayID,
			Name:        "rb",
			Slug:        "cons1234",
			RoutingMode: domainconsumer.RoutingModeRoleBased,
			RoleIDs:     []ids.RoleID{role.ID},
		},
	}
	data := appconsumer.NewData(gatewayID, nil, []*roledomain.Role{role})
	data.SetRegistryIndex(map[ids.RegistryID]*registrydomain.Registry{openai.ID: openai})

	lister := appproxy.NewModelsLister(approuting.NewResolver(), catalogmocks.NewService(t))
	list, err := lister.List(context.Background(), appproxy.ListModelsInput{
		Consumer: rc,
		Data:     data,
		RoleIDs:  []ids.RoleID{role.ID},
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	assertModelIDs(t, list, "gpt-5")
}

func TestListModels_GetFoundAndMissing(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, openai)
	rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{
		openai.ID: {Allowed: []string{"gpt-4o-mini"}},
	}
	lister := appproxy.NewModelsLister(approuting.NewResolver(), catalogmocks.NewService(t))
	in := appproxy.ListModelsInput{Consumer: rc}

	card, err := lister.Get(context.Background(), in, "gpt-4o-mini")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if card.ID != "gpt-4o-mini" || card.Object != "model" || card.OwnedBy != "openai" {
		t.Fatalf("card = %+v", card)
	}

	_, err = lister.Get(context.Background(), in, "gpt-4-forbidden")
	if !errors.Is(err, appproxy.ErrModelNotFound) {
		t.Fatalf("Get missing = %v, want ErrModelNotFound", err)
	}
}

func TestListModels_SkipsRoutingRefs(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	openai := backendFor(gatewayID, "openai")
	rc := routableConsumerWith(gatewayID, openai)
	rc.Consumer.ModelPolicies = domainconsumer.ModelPolicies{
		openai.ID: {Allowed: []string{"gpt-4o", "@openai/gpt-4o", "auto", "pool:fast"}},
	}

	list := listModels(t, rc, catalogmocks.NewService(t))
	assertModelIDs(t, list, "gpt-4o")
}

func TestListModels_EmptyConsumer(t *testing.T) {
	lister := appproxy.NewModelsLister(approuting.NewResolver(), catalogmocks.NewService(t))
	list, err := lister.List(context.Background(), appproxy.ListModelsInput{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if list.Object != "list" || len(list.Data) != 0 {
		t.Fatalf("list = %+v", list)
	}
}

func listModels(t *testing.T, rc *appconsumer.RoutableConsumer, catalog appcatalog.Service) *appproxy.ModelsList {
	t.Helper()
	lister := appproxy.NewModelsLister(approuting.NewResolver(), catalog)
	list, err := lister.List(context.Background(), appproxy.ListModelsInput{Consumer: rc})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	return list
}

func assertModelIDs(t *testing.T, list *appproxy.ModelsList, want ...string) {
	t.Helper()
	got := make([]string, 0, len(list.Data))
	for _, card := range list.Data {
		got = append(got, card.ID)
		if card.Object != "model" {
			t.Fatalf("card %q object = %q", card.ID, card.Object)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("ids = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ids = %v, want %v", got, want)
		}
	}
}

func assertOwnedBy(t *testing.T, list *appproxy.ModelsList, id, provider string) {
	t.Helper()
	for _, card := range list.Data {
		if card.ID == id {
			if card.OwnedBy != provider {
				t.Fatalf("owned_by(%s) = %q, want %q", id, card.OwnedBy, provider)
			}
			return
		}
	}
	t.Fatalf("model %q not in list", id)
}
