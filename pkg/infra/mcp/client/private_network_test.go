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

package client_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	mcpclient "github.com/NeuralTrust/TrustGate/pkg/infra/mcp/client"
)

// A target whose URL came from per-user variables (RestrictPrivateNetwork) must
// never reach a loopback / private address, even when the address itself is
// what the hostname resolves to — that is the DNS-rebinding case the host-name
// validation cannot catch. The same server is reachable for an admin-fixed URL.
func TestConnect_RestrictedTargetRefusesLoopbackUpstream(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := newUpstream(t, addEchoTool, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			next.ServeHTTP(w, r)
		})
	})

	_, err := mcpclient.New().Connect(context.Background(), appmcp.Target{URL: srv.URL, RestrictPrivateNetwork: true})
	if err == nil {
		t.Fatal("restricted target connected to a 127.0.0.1 upstream")
	}
	if !errors.Is(err, appmcp.ErrUnreachable) {
		t.Fatalf("error = %v, want ErrUnreachable", err)
	}
	if !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("error should name the private-network refusal: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("the upstream received %d request(s); the dial must be refused before any bytes are sent", hits.Load())
	}

	// Same upstream, admin-fixed URL: untouched.
	sess := connect(t, appmcp.Target{URL: srv.URL})
	if err := sess.Ping(context.Background()); err != nil {
		t.Fatalf("unrestricted connect to the same upstream failed: %v", err)
	}
}

// A hostname that resolves to loopback ("localhost" always does) is the
// rebinding shape: validation upstream would have refused the name, and the
// dialer refuses the address it resolves to.
func TestConnect_RestrictedTargetRefusesLoopbackHostname(t *testing.T) {
	t.Parallel()
	srv := newUpstream(t, addEchoTool, nil)
	_, port, _ := strings.Cut(strings.TrimPrefix(srv.URL, "http://"), ":")

	_, err := mcpclient.New().Connect(context.Background(), appmcp.Target{
		URL:                    "http://localhost:" + port + "/",
		RestrictPrivateNetwork: true,
	})
	if err == nil || !errors.Is(err, appmcp.ErrUnreachable) || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("error = %v, want ErrUnreachable with the private-network refusal", err)
	}
}
