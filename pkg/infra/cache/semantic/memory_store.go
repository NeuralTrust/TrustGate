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
	"log/slog"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
)

var _ Store = (*MemoryStore)(nil)

type memVector struct {
	vector   []float64
	response string
	expiry   time.Time
}

// MemoryStore is an in-process Store backed by a TTL map and brute-force cosine
// similarity. It suits development and small single-replica deployments;
// eviction is purely TTL-based.
type MemoryStore struct {
	mu     sync.Mutex
	vec    map[string][]memVector
	logger *slog.Logger
}

// NewMemoryStore builds an empty in-memory Store.
func NewMemoryStore(logger *slog.Logger) *MemoryStore {
	return &MemoryStore{
		vec:    make(map[string][]memVector),
		logger: logger,
	}
}

// EnsureIndex is a no-op for the in-memory backend.
func (s *MemoryStore) EnsureIndex(ctx context.Context, dimension int) error {
	return nil
}

// Store appends a response keyed by its embedding under the rule. A TTL of zero
// or less means the entry never expires.
func (s *MemoryStore) Store(ctx context.Context, entry Entry) error {
	if entry.Embedding == nil {
		return nil
	}
	vector := make([]float64, len(entry.Embedding.Value))
	copy(vector, entry.Embedding.Value)

	var expiry time.Time
	if entry.TTL > 0 {
		expiry = time.Now().Add(entry.TTL)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.vec[entry.RuleID] = append(s.sweep(entry.RuleID), memVector{
		vector:   vector,
		response: entry.Response,
		expiry:   expiry,
	})
	return nil
}

// Lookup returns the topK live cached responses for the rule, ordered by
// descending cosine similarity.
func (s *MemoryStore) Lookup(ctx context.Context, ruleID string, emb *embedding.Embedding, topK int) ([]Candidate, error) {
	if emb == nil || topK <= 0 {
		return nil, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	live := s.sweep(ruleID)
	s.vec[ruleID] = live

	candidates := make([]Candidate, 0, len(live))
	for _, v := range live {
		candidates = append(candidates, Candidate{
			Response:   v.response,
			Similarity: cosine(emb.Value, v.vector),
		})
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].Similarity > candidates[j].Similarity
	})
	if len(candidates) > topK {
		candidates = candidates[:topK]
	}
	return candidates, nil
}

func (s *MemoryStore) sweep(ruleID string) []memVector {
	entries := s.vec[ruleID]
	if len(entries) == 0 {
		return entries[:0]
	}
	now := time.Now()
	live := entries[:0]
	for _, e := range entries {
		if e.expiry.IsZero() || e.expiry.After(now) {
			live = append(live, e)
		}
	}
	return live
}

func cosine(a []float64, b []float64) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, normA, normB float64
	for i := range a {
		dot += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}
