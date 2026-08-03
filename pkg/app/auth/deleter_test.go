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

package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	consumermocks "github.com/NeuralTrust/TrustGate/pkg/domain/consumer/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/mock"
)

func TestDeleter_Delete_Success(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.AuthKind]()
	gwID := ids.New[ids.GatewayKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(&domain.Auth{ID: id, GatewayID: gwID}, nil).Once()
	repo.EXPECT().Delete(mock.Anything, gwID, id).Return(nil).Once()

	mgr := newCacheManager()
	mgr.GetTTLMap(cache.AuthTTLName).Set(id.String(), &domain.Auth{ID: id})

	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().ListByAuthID(mock.Anything, id).Return(nil, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	deleter := appauth.NewDeleter(repo, consumerRepo, mgr, publisher, newTestLogger(), nil)
	if err := deleter.Delete(context.Background(), gwID, id); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
	if _, ok := mgr.GetTTLMap(cache.AuthTTLName).Get(id.String()); ok {
		t.Fatal("expected cache entry to be evicted")
	}
}

func TestDeleter_Delete_BlockedWhenSoleIdPOfRoleBased(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.AuthKind]()
	gwID := ids.New[ids.GatewayKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(&domain.Auth{ID: id, GatewayID: gwID}, nil).Once()

	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().ListByAuthID(mock.Anything, id).Return([]*consumerdomain.Consumer{{
		ID:          ids.New[ids.ConsumerKind](),
		Slug:        "role-cons",
		RoutingMode: consumerdomain.RoutingModeRoleBased,
	}}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)

	deleter := appauth.NewDeleter(repo, consumerRepo, newCacheManager(), publisher, newTestLogger(), nil)
	err := deleter.Delete(context.Background(), gwID, id)
	if !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict when deleting the sole identity provider of a role_based consumer", err)
	}
	if !strings.Contains(err.Error(), "before deleting") {
		t.Fatalf("err = %v, want the message to reference deleting", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestDeleter_Delete_BlockedWhenSoleUsableIdPOfMCP(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.AuthKind]()
	gwID := ids.New[ids.GatewayKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(&domain.Auth{ID: id, GatewayID: gwID}, nil).Once()

	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().ListByAuthID(mock.Anything, id).Return([]*consumerdomain.Consumer{{
		ID:      ids.New[ids.ConsumerKind](),
		Slug:    "mcp-cons",
		Type:    consumerdomain.TypeMCP,
		AuthIDs: []ids.AuthID{id},
	}}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)

	deleter := appauth.NewDeleter(repo, consumerRepo, newCacheManager(), publisher, newTestLogger(), nil)
	err := deleter.Delete(context.Background(), gwID, id)
	if !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict when deleting the sole usable identity provider of an MCP consumer", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestDeleter_Delete_PropagatesError(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.AuthKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(nil, domain.ErrNotFound).Once()

	publisher := cachemocks.NewEventPublisher(t)

	deleter := appauth.NewDeleter(repo, consumermocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)
	if err := deleter.Delete(context.Background(), ids.New[ids.GatewayKind](), id); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestDeleter_Delete_WrongGateway(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.AuthKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(&domain.Auth{ID: id, GatewayID: ids.New[ids.GatewayKind]()}, nil).Once()

	publisher := cachemocks.NewEventPublisher(t)

	deleter := appauth.NewDeleter(repo, consumermocks.NewRepository(t), newCacheManager(), publisher, newTestLogger(), nil)
	if err := deleter.Delete(context.Background(), ids.New[ids.GatewayKind](), id); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound for cross-gateway delete", err)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestDeleter_Delete_DetachesReferencingConsumers(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	id := ids.New[ids.AuthKind]()
	gwID := ids.New[ids.GatewayKind]()
	repo.EXPECT().FindByID(mock.Anything, id).Return(&domain.Auth{ID: id, GatewayID: gwID}, nil).Once()
	repo.EXPECT().Delete(mock.Anything, gwID, id).Return(nil).Once()

	firstConsumer := ids.New[ids.ConsumerKind]()
	secondConsumer := ids.New[ids.ConsumerKind]()
	consumerRepo := consumermocks.NewRepository(t)
	consumerRepo.EXPECT().ListByAuthID(mock.Anything, id).Return([]*consumerdomain.Consumer{
		{ID: firstConsumer, Slug: "cons-a"},
		{ID: secondConsumer, Slug: "cons-b"},
	}, nil).Once()
	consumerRepo.EXPECT().DetachAuth(mock.Anything, firstConsumer, id).Return(nil).Once()
	consumerRepo.EXPECT().DetachAuth(mock.Anything, secondConsumer, id).Return(nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	// Two detached consumers still amount to a single gateway-wide invalidation.
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gwID.String()}).
		Return(nil).
		Once()

	deleter := appauth.NewDeleter(repo, consumerRepo, newCacheManager(), publisher, newTestLogger(), nil)
	if err := deleter.Delete(context.Background(), gwID, id); err != nil {
		t.Fatalf("Delete error: %v", err)
	}
}
