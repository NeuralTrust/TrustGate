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

package openapi

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestResolveAndDialEnforcesPublicDNSAnswers(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name                string
		ips                 []string
		publicOnly, allowed bool
	}{
		{"public", []string{"8.8.8.8"}, true, true},
		{"private_dns", []string{"10.1.2.3"}, true, false},
		{"mixed_dns", []string{"8.8.8.8", "10.1.2.3"}, true, false},
		{"loopback_dns", []string{"127.0.0.1"}, true, false},
		{"cgnat_dns", []string{"100.64.0.1"}, true, false},
		{"ula_dns", []string{"fd00::1"}, true, false},
		{"nat64_private", []string{"64:ff9b::a00:1"}, true, false},
		{"admin_private_dns", []string{"10.1.2.3"}, false, true},
		{"admin_cgnat_dns", []string{"100.64.0.1"}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var dialed string
			lookup := func(_ context.Context, host string) ([]net.IPAddr, error) {
				require.Equal(t, "user.example.com", host)
				var ips []net.IPAddr
				for _, ip := range tc.ips {
					ips = append(ips, net.IPAddr{IP: net.ParseIP(ip)})
				}
				return ips, nil
			}
			dial := func(_ context.Context, _ string, address string) (net.Conn, error) {
				dialed = address
				a, b := net.Pipe()
				require.NoError(t, b.Close())
				return a, nil
			}
			conn, err := resolveAndDial(context.Background(), "tcp", "user.example.com:443", tc.publicOnly, lookup, dial)
			if tc.allowed {
				require.NoError(t, err)
				require.Equal(t, net.JoinHostPort(tc.ips[0], "443"), dialed)
				require.NoError(t, conn.Close())
			} else {
				require.Error(t, err)
				require.Empty(t, dialed)
			}
		})
	}
}

func TestPublicHTTPClientDoesNotDelegateResolutionToProxy(t *testing.T) {
	t.Parallel()
	client := NewPublicHTTPClient(time.Second)
	require.Nil(t, client.Transport.(*http.Transport).Proxy)
}
