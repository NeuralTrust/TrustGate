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

package policy_test

import (
	"context"
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport/configsynctest"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/policy/mocks"
	"github.com/stretchr/testify/mock"
)

func TestCreator_Create_SignalsOnSuccess(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	gwID := ids.New[ids.GatewayKind]()
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()

	signaler := &configsynctest.FakeSignaler{}
	creator := apppolicy.NewCreator(repo, newRegistryMock(t, nil), newCacheManager(), newTestLogger(), signaler)

	if _, err := creator.Create(context.Background(), validCreateInput(gwID)); err != nil {
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
	creator := apppolicy.NewCreator(repo, newRegistryMock(t, nil), newCacheManager(), newTestLogger(), signaler)

	if _, err := creator.Create(context.Background(), validCreateInput(gwID)); err == nil {
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

	creator := apppolicy.NewCreator(repo, newRegistryMock(t, nil), newCacheManager(), newTestLogger(), nil)

	if _, err := creator.Create(context.Background(), validCreateInput(gwID)); err != nil {
		t.Fatalf("Create error: %v", err)
	}
}
