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
	"errors"
	"testing"

	appregistry "github.com/NeuralTrust/AgentGateway/pkg/app/registry"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/AgentGateway/pkg/domain/registry/mocks"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/cache/cachetest"
	"github.com/stretchr/testify/mock"
)

func TestDeleter_Delete_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.RegistryKind]()
	gwID := ids.New[ids.GatewayKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(&domain.Registry{ID: id, GatewayID: gwID}, nil).Once()
	repo.EXPECT().Delete(mock.Anything, id).Return(nil).Once()

	mgr := newCacheManager()
	mgr.GetTTLMap(cache.RegistryTTLName).Set(id.String(), "junk")

	deleter := appregistry.NewDeleter(repo, mgr, cachetest.NoopPublisher(), newTestLogger())
	if err := deleter.Delete(context.Background(), gwID, id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := mgr.GetTTLMap(cache.RegistryTTLName).Get(id.String()); ok {
		t.Fatal("cache entry should be evicted after Delete")
	}
}

func TestDeleter_Delete_NotFound(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.RegistryKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	deleter := appregistry.NewDeleter(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	err := deleter.Delete(context.Background(), ids.New[ids.GatewayKind](), id)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestDeleter_Delete_WrongGateway(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.RegistryKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(&domain.Registry{ID: id, GatewayID: ids.New[ids.GatewayKind]()}, nil).Once()

	deleter := appregistry.NewDeleter(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	err := deleter.Delete(context.Background(), ids.New[ids.GatewayKind](), id)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound for cross-gateway delete", err)
	}
}
