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

	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/policy/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/cachetest"
	"github.com/stretchr/testify/mock"
)

func TestScoper_SetGlobal_Success(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	existing := existingPolicy(t)
	existing.GatewayID = gwID

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().SetGlobal(mock.Anything, gwID, existing.ID, true).Return(nil).Once()

	scoper := apppolicy.NewScoper(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := scoper.SetGlobal(context.Background(), gwID, existing.ID)
	if err != nil {
		t.Fatalf("SetGlobal error: %v", err)
	}
	if !got.Global {
		t.Fatal("policy should be global after SetGlobal")
	}
}

func TestScoper_SetGlobal_AlreadyGlobalIsNoop(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	existing := existingPolicy(t)
	existing.GatewayID = gwID
	existing.Global = true

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	// No SetGlobal call expected: the state is unchanged.

	scoper := apppolicy.NewScoper(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := scoper.SetGlobal(context.Background(), gwID, existing.ID)
	if err != nil {
		t.Fatalf("SetGlobal error: %v", err)
	}
	if !got.Global {
		t.Fatal("policy should remain global")
	}
}

func TestScoper_SetGlobal_RejectsForeignGateway(t *testing.T) {
	t.Parallel()
	existing := existingPolicy(t)

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	scoper := apppolicy.NewScoper(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	_, err := scoper.SetGlobal(context.Background(), ids.New[ids.GatewayKind](), existing.ID)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestScoper_UnsetGlobal_Success(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	existing := existingPolicy(t)
	existing.GatewayID = gwID
	existing.Global = true

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().SetGlobal(mock.Anything, gwID, existing.ID, false).Return(nil).Once()

	scoper := apppolicy.NewScoper(repo, newCacheManager(), cachetest.NoopPublisher(), newTestLogger())
	got, err := scoper.UnsetGlobal(context.Background(), gwID, existing.ID)
	if err != nil {
		t.Fatalf("UnsetGlobal error: %v", err)
	}
	if got.Global {
		t.Fatal("policy should not be global after UnsetGlobal")
	}
}
