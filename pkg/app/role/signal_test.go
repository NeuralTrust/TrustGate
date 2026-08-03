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

package role_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport/configsynctest"
	approle "github.com/NeuralTrust/TrustGate/pkg/app/role"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/mock"
)

type failingRepositoryStub struct {
	repositoryStub
}

func (failingRepositoryStub) Save(context.Context, *domain.Role) error {
	return errors.New("boom")
}

func newSignalCreator(
	repo domain.Repository,
	publisher cache.EventPublisher,
	signaler configsyncport.SnapshotSignaler,
) approle.Creator {
	return approle.NewCreator(
		repo,
		cache.NewTTLMapManager(cache.RoleCacheTTL),
		publisher,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		signaler,
	)
}

func TestCreator_Create_SignalsOnSuccess(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	signaler := &configsynctest.FakeSignaler{}

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gatewayID.String()}).
		Return(nil).
		Once()

	creator := newSignalCreator(repositoryStub{}, publisher, signaler)

	if _, err := creator.Create(context.Background(), approle.CreateInput{GatewayID: gatewayID, Name: "analyst"}); err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if got := signaler.Count(); got != 1 {
		t.Fatalf("Signal count = %d, want 1", got)
	}
}

func TestCreator_Create_DoesNotSignalOnFailure(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()
	signaler := &configsynctest.FakeSignaler{}

	publisher := cachemocks.NewEventPublisher(t)

	creator := newSignalCreator(failingRepositoryStub{}, publisher, signaler)

	if _, err := creator.Create(context.Background(), approle.CreateInput{GatewayID: gatewayID, Name: "analyst"}); err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := signaler.Count(); got != 0 {
		t.Fatalf("Signal count = %d, want 0", got)
	}
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

func TestCreator_Create_NilSignalerIsSafe(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: gatewayID.String()}).
		Return(nil).
		Once()

	creator := newSignalCreator(repositoryStub{}, publisher, nil)

	if _, err := creator.Create(context.Background(), approle.CreateInput{GatewayID: gatewayID, Name: "analyst"}); err != nil {
		t.Fatalf("Create error: %v", err)
	}
}
