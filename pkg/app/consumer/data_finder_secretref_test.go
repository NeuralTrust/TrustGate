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

package consumer_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appsecretref "github.com/NeuralTrust/TrustGate/pkg/app/secretref"
	authmocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policymocks "github.com/NeuralTrust/TrustGate/pkg/domain/policy/mocks"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	backendmocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/stretchr/testify/mock"
)

func secretRefFixture(t *testing.T, regs []*registrydomain.Registry, loads int) (ids.GatewayID, *repomocks.Repository, *backendmocks.Repository, *policymocks.Repository) {
	t.Helper()
	gwID := ids.New[ids.GatewayKind]()
	ids_ := make([]ids.RegistryID, 0, len(regs))
	for _, r := range regs {
		r.GatewayID, r.Enabled = gwID, true
		ids_ = append(ids_, r.ID)
	}
	now := time.Now().UTC()
	cons := domain.Rehydrate(domain.RehydrateParams{
		ID: ids.New[ids.ConsumerKind](), GatewayID: gwID, Name: "c", Type: domain.TypeLLM,
		Slug: "X84Yhsy8", Active: true, RegistryIDs: ids_, CreatedAt: now, UpdatedAt: now,
	})
	repo := repomocks.NewRepository(t)
	repo.EXPECT().ListByGateway(mock.Anything, gwID).Return([]*domain.Consumer{cons}, nil).Times(loads)
	registryRepo := backendmocks.NewRepository(t)
	registryRepo.EXPECT().FindByIDs(mock.Anything, gwID, mock.Anything).Return(regs, nil).Times(loads)
	policyRepo := policymocks.NewRepository(t)
	policyRepo.EXPECT().ListByGateway(mock.Anything, gwID).Return(nil, nil).Times(loads)
	return gwID, repo, registryRepo, policyRepo
}

func literalRegistries() []*registrydomain.Registry {
	return []*registrydomain.Registry{
		{ID: ids.New[ids.RegistryKind](), LLMTarget: &registrydomain.LLMTarget{
			Provider: "openai", Auth: registrydomain.NewAPIKeyAuth("sk-live"),
			ProviderOptions: map[string]any{"headers": map[string]any{"X-Org": "org-1"}},
		}},
		{ID: ids.New[ids.RegistryKind](), MCPTarget: &registrydomain.MCPTarget{
			URL: "https://mcp", Headers: map[string]string{"X-K": "v"},
			Auth: &registrydomain.MCPAuth{Mode: registrydomain.MCPAuthModeStatic, Header: "Authorization", Value: "Bearer t"},
		}},
	}
}

// TestDataFinder_SecretRefsAreANoOpWithoutReferences builds the same gateway
// with and without the materializer and requires identical data, down to
// the registry pointers.
func TestDataFinder_SecretRefsAreANoOpWithoutReferences(t *testing.T) {
	t.Parallel()
	regs := literalRegistries()
	load := func(opts ...appconsumer.DataFinderOption) *appconsumer.Data {
		gwID, repo, registryRepo, policyRepo := secretRefFixture(t, regs, 1)
		finder := appconsumer.NewDataFinder(repo, registryRepo, policyRepo, authmocks.NewRepository(t), nil, newCacheManager(), newTestLogger(), opts...)
		data, err := finder.FindByGateway(context.Background(), gwID)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	plain := load()
	materialized := load(appconsumer.WithSecretReferences(appsecretref.NewMaterializer(appsecretref.MaterializerConfig{})))
	plain.GatewayID, materialized.GatewayID = ids.GatewayID{}, ids.GatewayID{}
	if !reflect.DeepEqual(plain.Consumers[0].Registries, materialized.Consumers[0].Registries) {
		t.Fatal("registries differ with the materializer and no references")
	}
	for _, r := range regs {
		got, ok := materialized.RegistryByID(r.ID)
		if !ok || got != r {
			t.Fatalf("registry %s was copied although it holds no reference", r.ID)
		}
	}
}

func TestDataFinder_UnresolvedReferenceNeverReachesTheData(t *testing.T) {
	t.Parallel()
	ref := "secret://vault/ai-gateway/openai#api_key"
	reg := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), LLMTarget: &registrydomain.LLMTarget{
		Provider: "openai", Auth: registrydomain.NewAPIKeyAuth(ref),
	}}
	gwID, repo, registryRepo, policyRepo := secretRefFixture(t, []*registrydomain.Registry{reg}, 1)
	finder := appconsumer.NewDataFinder(repo, registryRepo, policyRepo, authmocks.NewRepository(t), nil, newCacheManager(), newTestLogger(),
		appconsumer.WithSecretReferences(appsecretref.NewMaterializer(appsecretref.MaterializerConfig{})))
	data, err := finder.FindByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := data.RegistryByID(reg.ID)
	if !got.CredentialUnavailable() || got.LLMTarget.Auth.APIKey.APIKey != "" {
		t.Fatalf("with the feature off a reference must be empty and marked: %+v", got.LLMTarget.Auth.APIKey)
	}
	if data.Consumers[0].Registries[0] != got {
		t.Fatal("the consumer and the index must share the materialized copy")
	}
	if reg.LLMTarget.Auth.APIKey.APIKey != ref || reg.CredentialUnavailable() {
		t.Fatal("the repository's registry was modified")
	}
}

func TestDataFinder_InvalidationRebuildsTheGateway(t *testing.T) {
	t.Parallel()
	reg := &registrydomain.Registry{ID: ids.New[ids.RegistryKind](), LLMTarget: &registrydomain.LLMTarget{Provider: "openai", Auth: registrydomain.NewAPIKeyAuth("sk")}}
	gwID, repo, registryRepo, policyRepo := secretRefFixture(t, []*registrydomain.Registry{reg}, 2)
	manager := newCacheManager()
	finder := appconsumer.NewDataFinder(repo, registryRepo, policyRepo, authmocks.NewRepository(t), nil, manager, newTestLogger())
	if _, err := finder.FindByGateway(context.Background(), gwID); err != nil {
		t.Fatal(err)
	}
	appconsumer.InvalidateGatewayData(manager)(gwID)
	if _, err := finder.FindByGateway(context.Background(), gwID); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidateGatewayDataDropsLoadBalancers(t *testing.T) {
	t.Parallel()
	manager := newCacheManager()
	gw, other := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	lbs := manager.GetTTLMap(cache.LoadBalancerTTLName)
	lbs.Set(gw.String()+":consumer-1", "lb")
	lbs.Set(other.String()+":consumer-2", "lb")
	manager.GetTTLMap(cache.ConsumerDataTTLName).Set(gw.String(), "data")
	appconsumer.InvalidateGatewayData(manager)(gw)
	if _, ok := lbs.Get(gw.String() + ":consumer-1"); ok {
		t.Fatal("the gateway's load balancer still holds the old registries")
	}
	if _, ok := manager.GetTTLMap(cache.ConsumerDataTTLName).Get(gw.String()); ok {
		t.Fatal("the gateway's runtime data survived")
	}
	if _, ok := lbs.Get(other.String() + ":consumer-2"); !ok {
		t.Fatal("another gateway's load balancer was dropped")
	}
}
