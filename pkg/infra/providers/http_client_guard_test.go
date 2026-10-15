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

package providers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
)

// denyPrivateNetworks restores the production default (guard on) for one test.
func denyPrivateNetworks(t *testing.T) {
	t.Helper()
	netguard.SetAllowPrivate(false)
	t.Cleanup(func() { netguard.SetAllowPrivate(true) })
}

func TestPoolRefusesPrivateDestinations(t *testing.T) {
	denyPrivateNetworks(t)

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)

	targets := map[string]string{
		"loopback literal":     srv.URL,
		"localhost name":       "http://localhost:" + strings.Split(srv.URL, ":")[2],
		"cloud metadata":       "http://169.254.169.254/latest/meta-data",
		"rfc1918":              "http://10.0.0.5:8080/v1",
		"cgnat":                "http://100.64.0.1/v1",
		"ipv6 loopback":        "http://[::1]:8080/v1",
		"ipv4-mapped loopback": "http://[::ffff:127.0.0.1]:8080/v1",
		"aws ipv6 metadata":    "http://[fd00:ec2::254]/latest",
	}
	for name, target := range targets {
		t.Run(name, func(t *testing.T) {
			client := NewHTTPClientPool().Get("guard-"+name, 2*time.Second)
			_, err := client.Get(target)
			if !errors.Is(err, netguard.ErrBlockedDestination) {
				t.Fatalf("err = %v, want ErrBlockedDestination", err)
			}
		})
	}
	if hits.Load() != 0 {
		t.Fatalf("the private upstream received %d request(s)", hits.Load())
	}
}

func TestPoolAllowsPrivateDestinationsWhenOperatorOptsIn(t *testing.T) {
	denyPrivateNetworks(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	client := NewHTTPClientPool().Get("guard-optin", 2*time.Second)
	if _, err := client.Get(srv.URL); !errors.Is(err, netguard.ErrBlockedDestination) {
		t.Fatalf("flag off: err = %v, want a refusal", err)
	}
	SetAllowPrivateNetworks(true)
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("flag on: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestPoolRefusalNamesTheHostNotAnAddress(t *testing.T) {
	denyPrivateNetworks(t)
	_, err := NewHTTPClientPool().Get("guard-msg", 2*time.Second).Get("http://localhost:9/v1")
	if err == nil || !strings.Contains(err.Error(), "localhost") {
		t.Fatalf("err = %v, want one naming the host", err)
	}
	if strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("err = %v leaks the resolved address", err)
	}
}

func TestTrustedPoolSkipsTheGuard(t *testing.T) {
	denyPrivateNetworks(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	resp, err := NewTrustedHTTPClientPool().Get("guard-trusted", 2*time.Second).Get(srv.URL)
	if err != nil {
		t.Fatalf("trusted pool refused an operator-configured destination: %v", err)
	}
	_ = resp.Body.Close()
}
