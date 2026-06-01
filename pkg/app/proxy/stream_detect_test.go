package proxy_test

import (
	"net/url"
	"testing"

	appproxy "github.com/NeuralTrust/AgentGateway/pkg/app/proxy"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
)

func TestDetectStream(t *testing.T) {
	cases := []struct {
		name string
		req  *infracontext.RequestContext
		want bool
	}{
		{"nil request", nil, false},
		{"openai body stream true", &infracontext.RequestContext{Body: []byte(`{"model":"gpt","stream":true}`)}, true},
		{"openai body stream false", &infracontext.RequestContext{Body: []byte(`{"model":"gpt","stream":false}`)}, false},
		{"anthropic body stream true", &infracontext.RequestContext{Body: []byte(`{"model":"claude","stream":true,"messages":[]}`)}, true},
		{"no flag, no url signal", &infracontext.RequestContext{Body: []byte(`{"model":"gpt"}`)}, false},
		{"empty request", &infracontext.RequestContext{}, false},
		{
			"gemini path streamGenerateContent",
			&infracontext.RequestContext{Path: "/v1/models/gemini-2.5-pro:streamGenerateContent", Body: []byte(`{"contents":[]}`)},
			true,
		},
		{
			"gemini path generateContent (non-stream)",
			&infracontext.RequestContext{Path: "/v1/models/gemini-2.5-pro:generateContent", Body: []byte(`{"contents":[]}`)},
			false,
		},
		{
			"streamGenerateContent without colon is not a stream signal",
			&infracontext.RequestContext{Path: "/v1/logs/streamGenerateContentAudit", Body: []byte(`{"contents":[]}`)},
			false,
		},
		{
			"query alt=sse",
			&infracontext.RequestContext{Path: "/v1/x", Query: url.Values{"alt": {"sse"}}, Body: []byte(`{"contents":[]}`)},
			true,
		},
		{
			"url signal beats body stream false",
			&infracontext.RequestContext{Path: "/v1/models/x:streamGenerateContent", Body: []byte(`{"stream":false}`)},
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := appproxy.DetectStream(tc.req); got != tc.want {
				t.Fatalf("DetectStream() = %v, want %v", got, tc.want)
			}
		})
	}
}
