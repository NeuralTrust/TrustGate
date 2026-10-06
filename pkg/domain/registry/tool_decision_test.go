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
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/assert"
)

func TestDecisionsOfKeepsDecidedRowsSorted(t *testing.T) {
	t.Parallel()
	got := domain.DecisionsOf([]domain.PinnedTool{
		{Name: "b", Fingerprint: "2", Status: domain.ToolStatusRejected},
		{Name: "c", Fingerprint: "3", Status: domain.ToolStatusPending},
		{Name: "a", Fingerprint: "2", Status: domain.ToolStatusApproved},
		{Name: "a", Fingerprint: "1", Status: domain.ToolStatusApproved},
	})
	assert.Equal(t, []domain.ToolDecision{
		{Name: "a", Fingerprint: "1", Status: domain.ToolStatusApproved},
		{Name: "a", Fingerprint: "2", Status: domain.ToolStatusApproved},
		{Name: "b", Fingerprint: "2", Status: domain.ToolStatusRejected},
	}, got)
	assert.Nil(t, domain.DecisionsOf([]domain.PinnedTool{{Status: domain.ToolStatusPending}}))
}

func TestIsToolApproved(t *testing.T) {
	t.Parallel()
	reg := &domain.Registry{PinnedTools: []domain.ToolDecision{
		{Name: "ok", Fingerprint: "f1", Status: domain.ToolStatusApproved},
		{Name: "no", Fingerprint: "f2", Status: domain.ToolStatusRejected},
		{Name: "both", Fingerprint: "f3", Status: domain.ToolStatusApproved},
		{Name: "both", Fingerprint: "f3", Status: domain.ToolStatusRejected},
	}}
	assert.True(t, reg.IsToolApproved(domain.ToolRef{Name: "ok", Fingerprint: "f1"}))
	assert.False(t, reg.IsToolApproved(domain.ToolRef{Name: "ok", Fingerprint: "changed"}), "a changed definition is not approved")
	assert.False(t, reg.IsToolApproved(domain.ToolRef{Name: "no", Fingerprint: "f2"}))
	assert.False(t, reg.IsToolApproved(domain.ToolRef{Name: "both", Fingerprint: "f3"}), "rejected wins")
	assert.False(t, reg.IsToolApproved(domain.ToolRef{Name: "new", Fingerprint: "f9"}))
	assert.False(t, (&domain.Registry{}).IsToolApproved(domain.ToolRef{Name: "ok", Fingerprint: "f1"}))
}
