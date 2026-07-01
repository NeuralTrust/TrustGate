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
	"testing"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport/configsynctest"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/auth/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/cachetest"
	"github.com/stretchr/testify/mock"
)

func signalCreateInput(gwID ids.GatewayID) appauth.CreateInput {
	return appauth.CreateInput{
		GatewayID: gwID,
		Name:      "client-key",
		Type:      domain.TypeAPIKey,
		Enabled:   true,
		Config:    validConfig(),
	}
}

func TestCreator_Create_SignalsOnSuccess(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()

	signaler := &configsynctest.FakeSignaler{}
	creator := appauth.NewCreator(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger(), signaler)

	if _, err := creator.Create(context.Background(), signalCreateInput(gwID)); err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if got := signaler.Count(); got != 1 {
		t.Fatalf("Signal count = %d, want 1", got)
	}
}

func TestCreator_Create_DoesNotSignalOnFailure(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(errors.New("boom")).Once()

	signaler := &configsynctest.FakeSignaler{}
	creator := appauth.NewCreator(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger(), signaler)

	if _, err := creator.Create(context.Background(), signalCreateInput(gwID)); err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := signaler.Count(); got != 0 {
		t.Fatalf("Signal count = %d, want 0", got)
	}
}

func TestCreator_Create_NilSignalerIsSafe(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()

	creator := appauth.NewCreator(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger(), nil)

	if _, err := creator.Create(context.Background(), signalCreateInput(gwID)); err != nil {
		t.Fatalf("Create error: %v", err)
	}
}
