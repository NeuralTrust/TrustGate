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

package registry_test

import (
	"context"
	"testing"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/app/registry/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/mock"
)

type blankingMaterializer struct{}

func (blankingMaterializer) Registries(_ context.Context, _ ids.GatewayID, byID map[ids.RegistryID]*domain.Registry) map[ids.RegistryID]*domain.Registry {
	out := map[ids.RegistryID]*domain.Registry{}
	for id, r := range byID {
		c := *r
		c.MarkCredentialUnavailable()
		out[id] = &c
	}
	return out
}

func TestRuntimeFinderMaterializesFindByIDOnly(t *testing.T) {
	t.Parallel()
	gw, id := ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind]()
	stored := &domain.Registry{ID: id, GatewayID: gw}
	inner := mocks.NewFinder(t)
	inner.EXPECT().FindByID(mock.Anything, gw, id).Return(stored, nil).Once()
	inner.EXPECT().List(mock.Anything, mock.Anything).Return([]*domain.Registry{stored}, 1, nil).Once()
	f := appregistry.NewRuntimeFinder(inner, blankingMaterializer{})
	got, err := f.FindByID(context.Background(), gw, id)
	if err != nil || got == stored || !got.CredentialUnavailable() {
		t.Fatalf("FindByID returned the stored registry: %v", err)
	}
	if stored.CredentialUnavailable() {
		t.Fatal("the stored registry was modified")
	}
	list, _, _ := f.List(context.Background(), domain.ListFilter{})
	if list[0] != stored {
		t.Fatal("List must return registries as stored")
	}
}

func TestConnectionTesterReportsUnresolvedReferences(t *testing.T) {
	t.Parallel()
	gw, id := ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind]()
	marked := &domain.Registry{ID: id, GatewayID: gw, LLMTarget: &domain.LLMTarget{Provider: "openai"}}
	marked.MarkCredentialUnavailable()
	finder := mocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, gw, id).Return(marked, nil).Once()
	svc := appregistry.NewConnectionTester(finder, nil, newTestLogger())
	res, err := svc.Test(context.Background(), appregistry.TestConnectionInput{GatewayID: gw, RegistryID: &id})
	if err != nil || res.OK || res.Stage != appregistry.StageSecretUnavailable {
		t.Fatalf("result %+v, err %v", res, err)
	}
}
