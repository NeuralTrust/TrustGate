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

package requestmeta

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveGCPClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.129.0.0/23"), netip.MustParsePrefix("130.211.0.0/22")}
	for _, tc := range []struct{ name, mode, peer, xff, want string }{
		{"default ignores forwarding", "peer", "10.129.0.2:443", "203.0.113.42, 34.1.2.3", "10.129.0.2"},
		{"untrusted peer", "gcp", "10.0.0.2:443", "203.0.113.42, 34.1.2.3", "10.0.0.2"},
		{"regional appended pair", "gcp", "10.129.1.9:443", "203.0.113.42, 34.1.2.3", "203.0.113.42"},
		{"global ignores spoofed left values", "gcp", "130.211.1.2:443", "attacker garbage, 192.0.2.99, 203.0.113.42, 34.1.2.3", "203.0.113.42"},
		{"private internal client", "gcp", "10.129.0.2:443", "10.0.1.5, 10.0.2.8", "10.0.1.5"},
		{"ipv6 client", "gcp", "10.129.0.2:443", "2001:db8::42, 2001:db8::1", "2001:db8::42"},
		{"mapped addresses", "gcp", "[::ffff:10.129.0.2]:443", "::ffff:203.0.113.42, 34.1.2.3", "203.0.113.42"},
		{"missing header", "gcp", "10.129.0.2", "", "10.129.0.2"},
		{"single spoofed value", "gcp", "10.129.0.2", "192.0.2.99", "10.129.0.2"},
		{"invalid client", "gcp", "10.129.0.2", "unknown, 34.1.2.3", "10.129.0.2"},
		{"invalid frontend", "gcp", "10.129.0.2", "203.0.113.42, bad", "10.129.0.2"},
		{"unspecified client", "gcp", "10.129.0.2", "0.0.0.0, 34.1.2.3", "10.129.0.2"},
		{"zone client", "gcp", "10.129.0.2", "fe80::1%eth0, 34.1.2.3", "10.129.0.2"},
		{"header injection", "gcp", "10.129.0.2", "bad\r\n, 203.0.113.42, 34.1.2.3", "10.129.0.2"},
		{"too long", "gcp", "10.129.0.2", strings.Repeat("x", 4096) + ", 203.0.113.42, 34.1.2.3", "10.129.0.2"},
		{"too many hops", "gcp", "10.129.0.2", strings.Repeat("1.1.1.1,", 32) + "203.0.113.42, 34.1.2.3", "10.129.0.2"},
	} {
		t.Run(tc.name, func(t *testing.T) { assert.Equal(t, tc.want, NewIPResolver(tc.mode, trusted)(tc.peer, tc.xff)) })
	}
}
