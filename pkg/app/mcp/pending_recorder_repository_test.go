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

package mcp_test

import (
	"context"
	"errors"
	"testing"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestRepositoryPendingRecorder_WritesPendingRowsOnly(t *testing.T) {
	gw, _ := ids.NewV7[ids.GatewayKind]()
	reg, _ := ids.NewV7[ids.RegistryKind]()
	cand, err := registrydomain.NewToolCandidate("a", "d", nil)
	require.NoError(t, err)

	repo := mocks.NewPinnedToolRepository(t)
	repo.EXPECT().UpsertPending(mock.Anything, gw, reg, []registrydomain.ToolCandidate{cand}).Return(1, 0, nil).Once()

	require.NoError(t, appmcp.NewRepositoryPendingRecorder(repo, nil).Record(context.Background(), gw, reg, []registrydomain.ToolCandidate{cand}))
}

func TestRepositoryPendingRecorder_WrapsRepositoryError(t *testing.T) {
	gw, _ := ids.NewV7[ids.GatewayKind]()
	reg, _ := ids.NewV7[ids.RegistryKind]()
	boom := errors.New("boom")
	repo := mocks.NewPinnedToolRepository(t)
	repo.EXPECT().UpsertPending(mock.Anything, gw, reg, mock.Anything).Return(0, 0, boom)

	err := appmcp.NewRepositoryPendingRecorder(repo, nil).Record(context.Background(), gw, reg, nil)
	assert.ErrorIs(t, err, boom)
}

func TestRepositoryPendingRecorder_CapDropIsNotAnError(t *testing.T) {
	gw, _ := ids.NewV7[ids.GatewayKind]()
	reg, _ := ids.NewV7[ids.RegistryKind]()
	repo := mocks.NewPinnedToolRepository(t)
	repo.EXPECT().UpsertPending(mock.Anything, gw, reg, mock.Anything).Return(0, 3, nil)

	assert.NoError(t, appmcp.NewRepositoryPendingRecorder(repo, nil).Record(context.Background(), gw, reg, nil))
}
