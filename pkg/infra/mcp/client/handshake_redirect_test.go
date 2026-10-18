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

package client

import (
	"io"
	"net/http"
	"strings"
	"testing"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
)

func TestRoundTrip_HTTPSRedirectToHTTPIsRefused(t *testing.T) {
	const body = "upstream-secret-body"
	rt := &handshakeRoundTripper{transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusTemporaryRedirect,
			Header:     http.Header{"Location": []string{"http://mcp.example/mcp"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    r,
		}, nil
	})}
	req, err := http.NewRequest(http.MethodPost, "https://mcp.example/mcp", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_, err = rt.RoundTrip(req)
	if err == nil {
		t.Fatal("https to http must not be returned as a response to follow")
	}
	got := appmcp.ClassifyUpstreamFailure(err)
	if got == nil || got.Kind != appmcp.UpstreamFailureDowngrade || got.StatusPhrase() != "redirect to http:// refused" {
		t.Fatalf("classified = %+v, err = %v", got, err)
	}
	if strings.Contains(err.Error(), body) || strings.Contains(err.Error(), "mcp.example") {
		t.Fatalf("downgrade error echoes the upstream: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
