// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
