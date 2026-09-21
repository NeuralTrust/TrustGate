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

package consumer

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func bucketPolicy(slug string, scope *policydomain.MCPScope) *policydomain.Policy {
	return &policydomain.Policy{ID: ids.New[ids.PolicyKind](), Slug: slug, Enabled: true, MCPScope: scope}
}

func TestPartitionScoped_OneBucketPerScopeDimension(t *testing.T) {
	t.Parallel()
	registryID := ids.New[ids.RegistryKind]()
	cases := []struct {
		name   string
		scope  *policydomain.MCPScope
		bucket func(scopeBuckets) []*policydomain.Policy
	}{
		{
			name:   "no scope runs on every plane",
			scope:  nil,
			bucket: func(b scopeBuckets) []*policydomain.Policy { return b.unscoped },
		},
		{
			name:   "groups alone crosses into a non-MCP plane",
			scope:  &policydomain.MCPScope{Groups: []string{"finance"}},
			bucket: func(b scopeBuckets) []*policydomain.Policy { return b.crossing },
		},
		{
			name:   "except_groups alone crosses too: it is the same dimension",
			scope:  &policydomain.MCPScope{ExceptGroups: []string{"finance"}},
			bucket: func(b scopeBuckets) []*policydomain.Policy { return b.crossing },
		},
		{
			name:   "a registry is MCP only",
			scope:  &policydomain.MCPScope{RegistryIDs: []ids.RegistryID{registryID}},
			bucket: func(b scopeBuckets) []*policydomain.Policy { return b.mcpOnly },
		},
		{
			name: "a tool is MCP only",
			scope: &policydomain.MCPScope{
				Tools: []policydomain.MCPToolRef{{RegistryID: registryID, Tool: "run_query"}},
			},
			bucket: func(b scopeBuckets) []*policydomain.Policy { return b.mcpOnly },
		},
		{
			name: "a destination pins a group scope to MCP",
			scope: &policydomain.MCPScope{
				RegistryIDs: []ids.RegistryID{registryID},
				Groups:      []string{"finance"},
			},
			bucket: func(b scopeBuckets) []*policydomain.Policy { return b.mcpOnly },
		},
		{
			name:   "an empty scope is a tombstone",
			scope:  &policydomain.MCPScope{},
			bucket: func(b scopeBuckets) []*policydomain.Policy { return b.dormant },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pol := bucketPolicy("trustguard", tc.scope)
			buckets := partitionScoped([]*policydomain.Policy{pol})
			landed := tc.bucket(buckets)
			require.Len(t, landed, 1)
			assert.Equal(t, pol.ID, landed[0].ID)
			total := len(buckets.unscoped) + len(buckets.crossing) + len(buckets.mcpOnly) + len(buckets.dormant)
			assert.Equal(t, 1, total, "a policy lands in exactly one bucket")
		})
	}
}

// A tombstone enters none of the three buckets a plan is built from, and still
// reaches the MCP plane's scoped list so it is reported as skipped rather than
// silently dropped (RUN-1621, rule 1).
func TestPartitionScoped_TombstoneEntersNoPlanButStaysScoped(t *testing.T) {
	t.Parallel()
	tombstone := bucketPolicy("trustguard", &policydomain.MCPScope{})
	buckets := partitionScoped([]*policydomain.Policy{tombstone})

	assert.Empty(t, buckets.unscoped)
	assert.Empty(t, buckets.crossing)
	assert.Empty(t, buckets.mcpOnly)
	require.Len(t, buckets.dormant, 1)
	require.Len(t, buckets.scoped, 1)
	assert.Equal(t, tombstone.ID, buckets.scoped[0].ID)
}

func TestPartitionScoped_ScopedKeepsLoadOrderAcrossBuckets(t *testing.T) {
	t.Parallel()
	crossing := bucketPolicy("a", &policydomain.MCPScope{Groups: []string{"finance"}})
	tombstone := bucketPolicy("b", &policydomain.MCPScope{})
	destination := bucketPolicy("c", &policydomain.MCPScope{RegistryIDs: []ids.RegistryID{ids.New[ids.RegistryKind]()}})

	buckets := partitionScoped([]*policydomain.Policy{crossing, tombstone, destination, nil})

	require.Len(t, buckets.scoped, 3)
	assert.Equal(t, []ids.PolicyID{crossing.ID, tombstone.ID, destination.ID},
		[]ids.PolicyID{buckets.scoped[0].ID, buckets.scoped[1].ID, buckets.scoped[2].ID},
		"the MCP plane must keep seeing its scoped policies in load order")
}
