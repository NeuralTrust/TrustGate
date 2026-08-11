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
	"errors"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/mock"
)

func TestDeleter_Delete_Success(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.ConsumerKind]()
	gwID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, id).Return(&domain.Consumer{ID: id, GatewayID: gwID}, nil).Once()
	repo.EXPECT().Delete(mock.Anything, gwID, id).Return(nil).Once()

	mgr := newCacheManager()
	mgr.GetTTLMap(cache.ConsumerTTLName).Set(id.String(), &domain.Consumer{ID: id})

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	d := appconsumer.NewDeleter(repo, mgr, publisher, newTestLogger(), nil)
	if err := d.Delete(context.Background(), gwID, id); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	if _, ok := mgr.GetTTLMap(cache.ConsumerTTLName).Get(id.String()); ok {
		t.Fatal("cache entry should have been evicted")
	}
}

func TestDeleter_Delete_NotFound(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.ConsumerKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	publisher := cachemocks.NewEventPublisher(t)
	d := appconsumer.NewDeleter(repo, newCacheManager(), publisher, newTestLogger(), nil)
	if err := d.Delete(context.Background(), ids.New[ids.GatewayKind](), id); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestDeleter_Delete_WrongGateway(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.ConsumerKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, id).Return(&domain.Consumer{ID: id, GatewayID: ids.New[ids.GatewayKind]()}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	d := appconsumer.NewDeleter(repo, newCacheManager(), publisher, newTestLogger(), nil)
	if err := d.Delete(context.Background(), ids.New[ids.GatewayKind](), id); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound for cross-gateway delete", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestDeleter_Delete_PropagatesRepoError(t *testing.T) {
	t.Parallel()
	id := ids.New[ids.ConsumerKind]()
	gwID := ids.New[ids.GatewayKind]()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, id).Return(&domain.Consumer{ID: id, GatewayID: gwID}, nil).Once()
	repo.EXPECT().Delete(mock.Anything, gwID, id).Return(domain.ErrAlreadyExists).Once()

	publisher := cachemocks.NewEventPublisher(t)
	d := appconsumer.NewDeleter(repo, newCacheManager(), publisher, newTestLogger(), nil)
	if err := d.Delete(context.Background(), gwID, id); !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}
