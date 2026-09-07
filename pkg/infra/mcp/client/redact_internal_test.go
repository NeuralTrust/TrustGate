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
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
)

func TestRedactURL(t *testing.T) {
	cases := map[string]string{
		"https://mcp.brightdata.com/mcp?token=supersecret123":                       "https://mcp.brightdata.com/mcp?token=***",
		"https://mcp.browserbase.com/mcp?browserbaseApiKey=bb_live_abc&sessionId=1": "https://mcp.browserbase.com/mcp?browserbaseApiKey=***&sessionId=***",
		"https://user:pw@api.example.com/mcp#frag":                                  "https://api.example.com/mcp",
		"https://mcp.linear.app/mcp":                                                "https://mcp.linear.app/mcp",
		"http://127.0.0.1:1/mcp":                                                    "http://127.0.0.1:1/mcp",
		"::not a url?token=supersecret123":                                          "::not a url",
	}
	for in, want := range cases {
		if got := redactURL(in); got != want {
			t.Errorf("redactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// net/http's *url.Error carries the full request URL, query string included, so
// the underlying error — not just the URL wrapUnreachable prints — must be
// scrubbed, while the chain stays intact for errors.Is / errors.As.
func TestWrapUnreachable_RedactsSecretQueryValuesEverywhere(t *testing.T) {
	const raw = "https://mcp.brightdata.com/mcp?token=supersecret123"
	inner := &url.Error{Op: "Post", URL: raw, Err: errors.New("dial tcp: connection refused")}
	wrapped := fmt_Errorf_chain(inner)

	err := wrapUnreachable(raw, wrapped)
	msg := err.Error()
	if strings.Contains(msg, "supersecret123") {
		t.Fatalf("secret leaked into the error text: %s", msg)
	}
	if !strings.Contains(msg, "token=***") {
		t.Fatalf("redacted URL shape missing from error text: %s", msg)
	}
	if !errors.Is(err, appmcp.ErrUnreachable) {
		t.Fatalf("error lost ErrUnreachable: %v", err)
	}
	if !errors.Is(err, appmcp.ErrUpstreamUnauthorized) {
		t.Fatalf("error lost the inner sentinel through redaction: %v", err)
	}
	var uerr *url.Error
	if !errors.As(err, &uerr) {
		t.Fatalf("error chain lost the *url.Error: %v", err)
	}

	// The value on its own (an upstream echoing the token in a body) is masked too.
	loose := wrapUnreachable(raw, errors.New("upstream said: invalid token supersecret123 (escaped supersecret123)"))
	if strings.Contains(loose.Error(), "supersecret123") {
		t.Fatalf("loose secret leaked: %s", loose.Error())
	}

	// A target without a query is passed through untouched.
	plain := errors.New("dial tcp 127.0.0.1:1: connection refused")
	if got := wrapUnreachable("http://127.0.0.1:1/mcp", plain); !errors.Is(got, plain) || !strings.Contains(got.Error(), plain.Error()) {
		t.Fatalf("plain error mangled: %v", got)
	}
}

// fmt_Errorf_chain wraps like Connect does: an ErrUpstreamUnauthorized layer
// over the transport error, so the test can prove both sentinels survive.
func fmt_Errorf_chain(inner error) error {
	return &redactedChainProbe{inner: inner}
}

type redactedChainProbe struct{ inner error }

func (p *redactedChainProbe) Error() string {
	return appmcp.ErrUpstreamUnauthorized.Error() + ": " + p.inner.Error()
}
func (p *redactedChainProbe) Unwrap() []error {
	return []error{appmcp.ErrUpstreamUnauthorized, p.inner}
}

func TestIsPublicUnicast(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "127.1.2.3", "::1",
		"10.0.0.5", "172.16.0.1", "192.168.1.1",
		"169.254.169.254", "fe80::1",
		"100.64.0.1", "100.127.255.254",
		"0.0.0.0", "0.1.2.3", "::",
		"224.0.0.1", "ff02::1",
		"255.255.255.255", "240.0.0.1",
		"192.0.0.1",
		"fd00::1", "fc00::1",
		"::ffff:10.0.0.1", "::ffff:127.0.0.1",
		"64:ff9b::a00:1", // NAT64 of 10.0.0.1
		"100::1",
	}
	for _, s := range blocked {
		if isPublicUnicast(net.ParseIP(s)) {
			t.Errorf("%s classified as public", s)
		}
	}
	public := []string{"8.8.8.8", "1.1.1.1", "52.94.76.1", "2606:4700::1111", "2001:4860:4860::8888", "64:ff9b::808:808"}
	for _, s := range public {
		if !isPublicUnicast(net.ParseIP(s)) {
			t.Errorf("%s classified as non-public", s)
		}
	}
	if isPublicUnicast(nil) {
		t.Error("nil ip classified as public")
	}
}
