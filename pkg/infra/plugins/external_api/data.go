package external_api

type ExternalAPIData struct {
	Endpoint   string `json:"endpoint"`
	Method     string `json:"method"`
	StatusCode int    `json:"status_code"`
	DurationMs int64  `json:"duration_ms"`
	Response   string `json:"response"`
}
