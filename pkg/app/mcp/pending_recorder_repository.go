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

package mcp

import (
	"context"
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// RepositoryPendingRecorder is the full plane's persistence port for pending
// tools: it writes straight through the pinned tool repository, which only
// inserts missing rows and never touches a decided one. The DB-less plane uses
// the config-sync client instead.
type RepositoryPendingRecorder struct {
	repo registrydomain.PinnedToolRepository
}

func NewRepositoryPendingRecorder(repo registrydomain.PinnedToolRepository) *RepositoryPendingRecorder {
	return &RepositoryPendingRecorder{repo: repo}
}

var _ PendingToolRecorder = (*RepositoryPendingRecorder)(nil)

func (r *RepositoryPendingRecorder) Record(
	ctx context.Context,
	gatewayID ids.GatewayID,
	registryID ids.RegistryID,
	tools []registrydomain.ToolCandidate,
) error {
	if _, err := r.repo.UpsertPending(ctx, gatewayID, registryID, tools); err != nil {
		return fmt.Errorf("pending tools: %w", err)
	}
	return nil
}
