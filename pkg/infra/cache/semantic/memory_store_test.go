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

package semantic

import (
	"context"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func emb(value ...float64) *embedding.Embedding {
	return &embedding.Embedding{Value: value}
}

func TestMemoryStoreLookupTopKOrdering(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(nil)

	const rule = "rule-a"
	require.NoError(t, store.Store(ctx, Entry{RuleID: rule, Embedding: emb(1, 0), Response: "exact"}))
	require.NoError(t, store.Store(ctx, Entry{RuleID: rule, Embedding: emb(0.9, 0.1), Response: "close"}))
	require.NoError(t, store.Store(ctx, Entry{RuleID: rule, Embedding: emb(0, 1), Response: "orthogonal"}))

	candidates, err := store.Lookup(ctx, rule, emb(1, 0), 2)
	require.NoError(t, err)
	require.Len(t, candidates, 2)

	assert.Equal(t, "exact", candidates[0].Response)
	assert.Equal(t, "close", candidates[1].Response)
	assert.Greater(t, candidates[0].Similarity, candidates[1].Similarity)
	assert.InDelta(t, 1.0, candidates[0].Similarity, 1e-9)
}

func TestMemoryStoreTTLEviction(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(nil)

	const rule = "rule-ttl"
	require.NoError(t, store.Store(ctx, Entry{
		RuleID:    rule,
		Embedding: emb(1, 0),
		Response:  "ephemeral",
		TTL:       30 * time.Millisecond,
	}))

	candidates, err := store.Lookup(ctx, rule, emb(1, 0), 1)
	require.NoError(t, err)
	require.Len(t, candidates, 1)

	time.Sleep(60 * time.Millisecond)

	candidates, err = store.Lookup(ctx, rule, emb(1, 0), 1)
	require.NoError(t, err)
	assert.Empty(t, candidates)
}

func TestMemoryStoreEmptyRuleLookup(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(nil)

	candidates, err := store.Lookup(ctx, "unknown-rule", emb(1, 0), 5)
	require.NoError(t, err)
	assert.Empty(t, candidates)
}

func TestMemoryStoreZeroTTLNeverExpires(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(nil)

	const rule = "rule-permanent"
	require.NoError(t, store.Store(ctx, Entry{RuleID: rule, Embedding: emb(1, 0), Response: "kept"}))

	time.Sleep(20 * time.Millisecond)

	candidates, err := store.Lookup(ctx, rule, emb(1, 0), 1)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	assert.Equal(t, "kept", candidates[0].Response)
}
