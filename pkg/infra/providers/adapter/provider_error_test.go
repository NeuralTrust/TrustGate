package adapter

import "testing"

func TestBodyCarriesRetryableError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"empty", "", false},
		{"not json", "plain text", false},
		{"no error field", `{"choices":[]}`, false},
		{"anthropic overloaded", `{"error":{"type":"overloaded_error","message":"Overloaded"}}`, true},
		{"openai rate limit", `{"error":{"code":"rate_limit_exceeded","message":"slow down"}}`, true},
		{"insufficient quota", `{"error":{"type":"insufficient_quota"}}`, true},
		{"gemini unavailable", `{"error":{"status":"UNAVAILABLE","message":"service temporarily unavailable"}}`, true},
		{"terminal invalid request", `{"error":{"type":"invalid_request_error","message":"bad model"}}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := BodyCarriesRetryableError([]byte(tc.body)); got != tc.want {
				t.Errorf("BodyCarriesRetryableError(%q) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}
