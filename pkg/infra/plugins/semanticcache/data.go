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
