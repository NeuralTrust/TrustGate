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

// Package netguard refuses outbound connections to addresses that must never be
// reachable from a request a tenant can steer: loopback, RFC1918, link-local
// (cloud metadata included), carrier-grade NAT, unique-local IPv6 and the other
// reserved ranges. The check runs on the address that is about to be dialled,
// after DNS resolution, so a public-looking name that resolves to a private
// address, a rebinding answer and a redirect to an internal host are all
// covered by the same code path.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// ErrBlockedDestination is wrapped by every refusal so callers can detect it
// with errors.Is. The message names the host but never the resolved address,
// which would otherwise map the gateway's own network for the caller.
var ErrBlockedDestination = errors.New("destination is a private, loopback, link-local or otherwise non-public address")

// blockedPrefixes are ranges that net/netip does not classify as private but
// that never denote a public upstream.
var blockedPrefixes = mustPrefixes(
	"0.0.0.0/8",       // "this" network
	"100.64.0.0/10",   // carrier-grade NAT
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"240.0.0.0/4",     // reserved, includes the limited broadcast address
	"::/96",           // IPv4-compatible (deprecated), embeds an IPv4 address
	"::ffff:0:0/96",   // IPv4-mapped / SIIT; mapped forms are unmapped before this check
	"64:ff9b:1::/48",  // local-use NAT64
	"100::/64",        // IPv6 discard prefix
	"2001::/32",       // Teredo
	"2001:db8::/32",   // documentation
	"fec0::/10",       // deprecated site-local
)

var (
	nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour   = netip.MustParsePrefix("2002::/16")
)

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		out[i] = netip.MustParsePrefix(c)
	}
	return out
}

// IsPublicUnicast reports whether ip is a globally routable unicast address.
// IPv4-mapped IPv6 forms are judged as the IPv4 address they embed, and so are
// the NAT64 and 6to4 forms, which tunnel an IPv4 destination.
func IsPublicUnicast(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return publicAddr(addr.Unmap())
}

func publicAddr(addr netip.Addr) bool {
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	if addr.Is6() {
		switch {
		case nat64Prefix.Contains(addr):
			b := addr.As16()
			return publicAddr(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
		case sixToFour.Contains(addr):
			b := addr.As16()
			return publicAddr(netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}))
		}
	}
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// Guard dials only public destinations unless AllowPrivate says otherwise.
type Guard struct {
	// AllowPrivate is consulted on every dial. Nil means private destinations
	// are refused.
	AllowPrivate func() bool

	lookup func(ctx context.Context, host string) ([]net.IPAddr, error)
	dial   func(ctx context.Context, network, address string) (net.Conn, error)
}

// New returns a Guard that dials with dialer (a default one when nil).
func New(dialer *net.Dialer, allowPrivate func() bool) *Guard {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	}
	return &Guard{
		AllowPrivate: allowPrivate,
		lookup:       net.DefaultResolver.LookupIPAddr,
		dial:         dialer.DialContext,
	}
}

// DialContext is an http.Transport.DialContext. It resolves the host itself,
// refuses the dial when ANY answer is non-public (an attacker controls the
// answer set, so one private record in a mixed set poisons the whole name), and
// then connects to a checked IP literal, never to the name again.
func (g *Guard) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if g.AllowPrivate != nil && g.AllowPrivate() {
		return g.dial(ctx, network, address)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	if literal := net.ParseIP(host); literal != nil {
		ips = []net.IP{literal}
	} else {
		addrs, lerr := g.lookup(ctx, host)
		if lerr != nil {
			return nil, lerr
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses found for %s", host)
	}
	for _, ip := range ips {
		if !IsPublicUnicast(ip) {
			return nil, fmt.Errorf("%w: %s", ErrBlockedDestination, host)
		}
	}
	var lastErr error
	for _, ip := range ips {
		conn, derr := g.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}
