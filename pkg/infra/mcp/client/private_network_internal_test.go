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
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
)

// Every outbound path that serves a per-user target must route its transport
// through restrictedFor. These are white-box on purpose: the alternative is
// trusting that each new path remembers to, which is exactly what went wrong
// when the modern era was merged in and the probe was left out.
func TestRestrictedFor_FailsClosedForAnUnknownTransport(t *testing.T) {
	t.Parallel()
	restricted := appmcp.Target{URL: "https://tenant.example.com/mcp", RestrictPrivateNetwork: true}

	if got := restrictedFor(restricted, sharedHTTPTransport); got != restrictedUpstreamTransport {
		t.Fatal("a restricted target on the shared transport must get the address-restricted one")
	}
	// A transport this package did not build cannot carry the dialer check, so
	// the request is refused rather than sent unrestricted.
	refused := restrictedFor(restricted, http.DefaultTransport)
	_, err := refused.RoundTrip(httptest.NewRequest(http.MethodPost, restricted.URL, nil))
	if !errors.Is(err, errUnrestrictedTransport) {
		t.Fatalf("error = %v, want the fail-closed refusal", err)
	}
	// An admin-fixed URL is unaffected: it keeps whatever transport it was given.
	fixed := appmcp.Target{URL: "https://fixed.example.com/mcp"}
	if got := restrictedFor(fixed, http.DefaultTransport); got != http.DefaultTransport {
		t.Fatal("an admin-fixed target must keep its transport")
	}
}

// The probe is the first outbound request of an auto-mode connect, so a path
// that skips the restriction there leaks the user's credential to an unchecked
// address before any other guard runs.
func TestProbe_RestrictedTargetIsRefusedBeforeAnyRequest(t *testing.T) {
	t.Parallel()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(srv.Close)

	_, err := newProtocolProbe(sharedHTTPTransport).Probe(context.Background(), appmcp.Target{
		URL:                    srv.URL + "/mcp",
		RestrictPrivateNetwork: true,
		Headers:                map[string]string{"Authorization": "Bearer per-user-secret"},
	})
	if err == nil {
		t.Fatal("the probe reached a loopback upstream for a per-user target")
	}
	if hits.Load() != 0 {
		t.Fatalf("upstream received %d probe request(s); the dial must be refused first", hits.Load())
	}
}
