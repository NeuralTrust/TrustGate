package embedding

type SearchResult struct {
	Key   string
	Score float64 // Similarity score (1.0 is exact match, 0.0 is no similarity)
	Data  string
}
