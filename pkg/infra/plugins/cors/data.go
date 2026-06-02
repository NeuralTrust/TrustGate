package cors

// CorsData is the per-invocation trace payload describing the CORS decision.
type CorsData struct {
	Origin          string   `json:"origin"`
	Method          string   `json:"method"`
	Preflight       bool     `json:"preflight"`
	Allowed         bool     `json:"allowed"`
	RequestedMethod string   `json:"requested_method,omitempty"`
	AllowedMethods  []string `json:"allowed_methods,omitempty"`
}
