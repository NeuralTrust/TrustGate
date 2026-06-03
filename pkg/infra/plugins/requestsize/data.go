package requestsize

// RequestSizeLimiterData is the per-invocation trace payload describing the
// measured request size and whether a configured limit was exceeded.
type RequestSizeLimiterData struct {
	RequestSizeBytes   int    `json:"request_size_bytes"`
	RequestSizeChars   int    `json:"request_size_chars"`
	MaxSizeBytes       int    `json:"max_size_bytes"`
	MaxCharsPerRequest int    `json:"max_chars_per_request"`
	LimitExceeded      bool   `json:"limit_exceeded"`
	ExceededType       string `json:"exceeded_type,omitempty"`
}
