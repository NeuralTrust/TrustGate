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

	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
)

func TestVectorLiteral(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []float64
		want   string
	}{
		{name: "empty", values: nil, want: "[]"},
		{name: "single", values: []float64{1.5}, want: "[1.5]"},
		{name: "multiple", values: []float64{1, 2, 3}, want: "[1,2,3]"},
		{name: "negative and zero", values: []float64{-0.25, 0, 0.75}, want: "[-0.25,0,0.75]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := vectorLiteral(tt.values); got != tt.want {
				t.Fatalf("vectorLiteral(%v) = %q, want %q", tt.values, got, tt.want)
			}
		})
	}
}

func TestPgvectorEnsureIndexDimensionGuard(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		dimension int
		wantErr   bool
	}{
		{name: "supported dimension", dimension: pgvectorDimension, wantErr: false},
		{name: "too small", dimension: 768, wantErr: true},
		{name: "zero", dimension: 0, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			store := NewPgvectorStore(nil, nil)
			err := store.EnsureIndex(context.Background(), tt.dimension)
			if (err != nil) != tt.wantErr {
				t.Fatalf("EnsureIndex(%d) error = %v, wantErr %v", tt.dimension, err, tt.wantErr)
			}
		})
	}
}

func TestPgvectorStoreDimensionMismatchDegrades(t *testing.T) {
	t.Parallel()

	store := NewPgvectorStore(nil, nil)
	entry := Entry{
		RuleID:    "rule",
		Embedding: &embedding.Embedding{Value: []float64{0.1, 0.2, 0.3}},
		Response:  "body",
	}
	if err := store.Store(context.Background(), entry); err != nil {
		t.Fatalf("Store with wrong dimension should degrade to nil, got %v", err)
	}
	if err := store.Store(context.Background(), Entry{RuleID: "rule"}); err != nil {
		t.Fatalf("Store with nil embedding should degrade to nil, got %v", err)
	}
}

func TestPgvectorExactDegradesWithoutPool(t *testing.T) {
	t.Parallel()

	store := NewPgvectorStore(nil, nil)

	if err := store.PutExact(context.Background(), "rule", "key", "body", 0); err != nil {
		t.Fatalf("PutExact without a pool should degrade to nil, got %v", err)
	}
	resp, ok, err := store.GetExact(context.Background(), "rule", "key")
	if err != nil {
		t.Fatalf("GetExact without a pool should degrade to nil error, got %v", err)
	}
	if ok || resp != "" {
		t.Fatalf("GetExact without a pool should miss, got (%q, %v)", resp, ok)
	}
}
