package cors

type CorsData struct {
	Origin          string   `json:"origin"`
	Method          string   `json:"method"`
	Preflight       bool     `json:"preflight"`
	Allowed         bool     `json:"allowed"`
	RequestedMethod string   `json:"requested_method"`
	AllowedMethods  []string `json:"allowed_methods"`
}
