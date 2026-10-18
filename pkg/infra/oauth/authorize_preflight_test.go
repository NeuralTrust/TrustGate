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

package oauth_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
)

type preflightTransport struct {
	calls atomic.Int32
}

func (p *preflightTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if n := p.calls.Add(1); n > 1 {
		return nil, errFollowed(req)
	}
	header := make(http.Header)
	header.Set("Location", "http://evil.example/error?error=invalid_client")
	return &http.Response{
		StatusCode: http.StatusFound,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", 20<<10))),
		Request:    req,
	}, nil
}

type followedError struct{ url string }

func (e followedError) Error() string { return "followed redirect to " + e.url }

func errFollowed(req *http.Request) error {
	return followedError{url: req.URL.String()}
}

func TestPreflightAuthorize_DisallowedHostIsNotDialed(t *testing.T) {
	t.Parallel()
	transport := &preflightTransport{}
	reg := infraoauth.NewUpstreamRegistrar(newClaimStore(), &http.Client{Transport: transport})
	prober := reg.(interface {
		PreflightAuthorize(context.Context, string, string) (appoauth.AuthorizePreflight, error)
	})
	_, err := prober.PreflightAuthorize(context.Background(), "http://evil.example/authorize?client_id=abc", "https://api.vendor.example/oauth/authorize")
	if err == nil {
		t.Fatal("disallowed host was accepted")
	}
	if transport.calls.Load() != 0 {
		t.Fatalf("dials = %d, want the disallowed host refused before a request", transport.calls.Load())
	}
}

func TestPreflightAuthorize_RedirectIsNotFollowed(t *testing.T) {
	t.Parallel()
	transport := &preflightTransport{}
	reg := infraoauth.NewUpstreamRegistrar(newClaimStore(), &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			t.Fatal("the registrar client would have followed the redirect")
			return nil
		},
	})
	prober := reg.(interface {
		PreflightAuthorize(context.Context, string, string) (appoauth.AuthorizePreflight, error)
	})
	got, err := prober.PreflightAuthorize(context.Background(), "https://api.vendor.example/authorize?client_id=abc", "https://api.vendor.example/oauth/authorize")
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if transport.calls.Load() != 1 {
		t.Fatalf("dials = %d, want one request and no redirect", transport.calls.Load())
	}
	if got.Status != http.StatusFound || !strings.Contains(got.Location, "evil.example") {
		t.Fatalf("preflight = %+v, want the redirect response itself", got)
	}
	if len(got.Body) != 8<<10 {
		t.Fatalf("body = %d bytes, want the 8KiB cap", len(got.Body))
	}
}

func TestPreflightAuthorize_RefusesInsecureAndWrongPort(t *testing.T) {
	t.Parallel()
	allowed := "https://api.vendor.example/oauth/authorize"
	cases := []string{
		"http://api.vendor.example/authorize?client_id=abc",
		"https://api.vendor.example:8443/authorize?client_id=abc",
		"https://evil.example/authorize?client_id=abc",
	}
	for _, rawURL := range cases {
		t.Run(rawURL, func(t *testing.T) {
			t.Parallel()
			transport := &preflightTransport{}
			reg := infraoauth.NewUpstreamRegistrar(newClaimStore(), &http.Client{Transport: transport})
			prober := reg.(interface {
				PreflightAuthorize(context.Context, string, string) (appoauth.AuthorizePreflight, error)
			})
			if _, err := prober.PreflightAuthorize(context.Background(), rawURL, allowed); err == nil {
				t.Fatal("url was accepted")
			}
			if transport.calls.Load() != 0 {
				t.Fatalf("dials = %d, want the url refused before a request", transport.calls.Load())
			}
		})
	}
}

func TestPreflightAuthorize_ExplicitDefaultPortMatches(t *testing.T) {
	t.Parallel()
	transport := &preflightTransport{}
	reg := infraoauth.NewUpstreamRegistrar(newClaimStore(), &http.Client{Transport: transport})
	prober := reg.(interface {
		PreflightAuthorize(context.Context, string, string) (appoauth.AuthorizePreflight, error)
	})
	got, err := prober.PreflightAuthorize(context.Background(), "https://api.vendor.example:443/authorize?client_id=abc", "https://api.vendor.example/oauth/authorize")
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if transport.calls.Load() != 1 || got.Status != http.StatusFound {
		t.Fatalf("dials = %d status = %d, want the default port treated as 443", transport.calls.Load(), got.Status)
	}
}
