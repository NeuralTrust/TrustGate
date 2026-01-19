package code_sanitation

type CodeSanitationData struct {
	Sanitized bool                  `json:"sanitized"`
	Events    []CodeSanitationEvent `json:"events,omitempty"`
}

type CodeSanitationEvent struct {
	Source      string `json:"source"`             // e.g. "headers", "body", "query"
	Field       string `json:"field"`              // e.g. "User-Agent"
	Language    string `json:"language,omitempty"` // optional
	PatternName string `json:"pattern_name"`       // e.g. "default_html"
	Match       string `json:"match"`              // e.g. "<script>alert('XSS')</script>"
}
