package embedding

type Credentials struct {
	APIKey      string `json:"api_key,omitempty"` // #nosec G117
	HeaderName  string `json:"header_name,omitempty"`
	HeaderValue string `json:"header_value,omitempty"`
}

type Config struct {
	Provider    string      `json:"provider"`
	Model       string      `json:"model"`
	Credentials Credentials `json:"credentials,omitempty"`
}
