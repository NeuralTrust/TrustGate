package request_size_limiter

type RequestSizeLimiterData struct {
	RequestSizeBytes   int    `json:"request_size_bytes,omitempty"`
	RequestSizeChars   int    `json:"request_size_chars,omitempty"`
	MaxSizeBytes       int    `json:"max_size_bytes,omitempty"`
	MaxCharsPerRequest int    `json:"max_chars_per_request,omitempty"`
	LimitExceeded      bool   `json:"limit_exceeded"`
	ExceededType       string `json:"exceeded_type"`
}
