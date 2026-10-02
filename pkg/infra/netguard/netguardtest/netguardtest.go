// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package netguardtest builds clients for tests of code that must be guarded
// against indirect destinations: a trusted first hop (an httptest "issuer" on
// loopback) whose response points at a second, hostile loopback server.
package netguardtest

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
)

// ClientTrusting returns a client that dials the given host:port pairs without
// the guard and sends every other destination through the shared guard. Use it
// to stand in for a public identity provider while keeping the guard live for
// whatever that provider's documents point at.
func ClientTrusting(hostPorts ...string) *http.Client {
	trusted := make(map[string]struct{}, len(hostPorts))
	for _, hp := range hostPorts {
		trusted[hp] = struct{}{}
	}
	plain := &net.Dialer{Timeout: 5 * time.Second}
	tr := netguard.NewTransport()
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if _, ok := trusted[address]; ok {
			return plain.DialContext(ctx, network, address)
		}
		return netguard.Shared().DialContext(ctx, network, address)
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: tr, CheckRedirect: netguard.CheckRedirect}
}

// Deny switches the escape hatch off for one test and restores the previous
// state afterwards. Never combine it with t.Parallel: the flag is process-wide.
func Deny(t *testing.T) {
	t.Helper()
	prev := netguard.AllowPrivate()
	netguard.SetAllowPrivate(false)
	t.Cleanup(func() { netguard.SetAllowPrivate(prev) })
}

// Hostile starts a loopback server that counts hits, standing in for an
// internal service a tenant points an outbound URL at.
func Hostile(t *testing.T, h http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if h != nil {
			h(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}
