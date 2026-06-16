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

package semanticcache

// SemanticCacheData is the per-invocation trace payload describing the cache
// lookup/store decision and the similarity scoring that drove it.
type SemanticCacheData struct {
	CacheHit       bool    `json:"cache_hit"`
	Similarity     float64 `json:"similarity,omitempty"`
	Threshold      float64 `json:"threshold"`
	EmbeddingSize  int     `json:"embedding_size,omitempty"`
	VectorDim      int     `json:"vector_dimension,omitempty"`
	Stored         bool    `json:"stored"`
	Degraded       bool    `json:"degraded,omitempty"`
	DegradedReason string  `json:"degraded_reason,omitempty"`
}
