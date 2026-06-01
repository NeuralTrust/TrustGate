package adapter

import "testing"

func TestRequestWantsStream(t *testing.T) {
	cases := []struct {
		name         string
		body         string
		wantStream   bool
		wantExplicit bool
	}{
		{"openai stream true", `{"model":"gpt","stream":true}`, true, true},
		{"openai stream false", `{"model":"gpt","stream":false}`, false, true},
		{"openai absent", `{"model":"gpt"}`, false, false},
		{"anthropic stream true", `{"model":"claude","stream":true,"messages":[]}`, true, true},
		{"gemini contents (no flag)", `{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`, false, false},
		{"malformed json", `{not json`, false, false},
		{"empty body", ``, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotStream, gotExplicit := RequestWantsStream([]byte(tc.body))
			if gotStream != tc.wantStream || gotExplicit != tc.wantExplicit {
				t.Fatalf("RequestWantsStream(%s) = (%v, %v), want (%v, %v)",
					tc.body, gotStream, gotExplicit, tc.wantStream, tc.wantExplicit)
			}
		})
	}
}
