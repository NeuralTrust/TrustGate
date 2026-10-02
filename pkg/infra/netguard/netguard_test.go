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

package netguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIsPublicUnicast(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"public v4", "93.184.216.34", true},
		{"public v6", "2606:2800:220:1:248:1893:25c8:1946", true},
		{"loopback v4", "127.0.0.1", false},
		{"loopback v6", "::1", false},
		{"rfc1918 10/8", "10.1.2.3", false},
		{"rfc1918 172.16/12", "172.16.0.1", false},
		{"rfc1918 192.168/16", "192.168.1.1", false},
		{"cloud metadata v4", "169.254.169.254", false},
		{"cloud metadata aws ipv6", "fd00:ec2::254", false},
		{"link-local v6", "fe80::1", false},
		{"cgnat", "100.64.0.1", false},
		{"cgnat upper", "100.127.255.254", false},
		{"unique-local v6", "fc00::1", false},
		{"unique-local v6 fd", "fd12:3456::1", false},
		{"unspecified v4", "0.0.0.0", false},
		{"unspecified v6", "::", false},
		{"this network", "0.1.2.3", false},
		{"multicast v4", "224.0.0.1", false},
		{"multicast v6", "ff02::1", false},
		{"broadcast", "255.255.255.255", false},
		{"documentation", "203.0.113.7", false},
		{"mapped loopback", "::ffff:127.0.0.1", false},
		{"mapped rfc1918", "::ffff:10.0.0.1", false},
		{"mapped metadata", "::ffff:169.254.169.254", false},
		{"mapped public", "::ffff:93.184.216.34", true},
		{"nat64 embedding loopback", "64:ff9b::7f00:1", false},
		{"nat64 embedding public", "64:ff9b::5db8:d822", true},
		{"6to4 embedding rfc1918", "2002:0a00:0001::1", false},
		{"public just outside cgnat", "100.128.0.1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("bad test ip %q", tt.ip)
			}
			if got := IsPublicUnicast(ip); got != tt.want {
				t.Fatalf("IsPublicUnicast(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestIsPublicUnicastNilAndMalformed(t *testing.T) {
	if IsPublicUnicast(nil) || IsPublicUnicast(net.IP{1, 2, 3}) {
		t.Fatal("nil or malformed IP must not be public")
	}
}

// fakeNet builds a Guard whose DNS and TCP layers are scripted, so tests never
// depend on the host network. dialed records every address actually dialled.
func fakeNet(zone map[string][]string, target string) (*Guard, *[]string) {
	var dialed []string
	g := &Guard{
		lookup: func(_ context.Context, host string) ([]net.IPAddr, error) {
			answers, ok := zone[host]
			if !ok {
				return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
			}
			out := make([]net.IPAddr, 0, len(answers))
			for _, a := range answers {
				out = append(out, net.IPAddr{IP: net.ParseIP(a)})
			}
			return out, nil
		},
		dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialed = append(dialed, address)
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, target)
		},
	}
	return g, &dialed
}

func TestDialContextRefusals(t *testing.T) {
	zone := map[string][]string{
		"localhost.test": {"127.0.0.1"},
		"internal.test":  {"10.0.0.5"},
		"meta.test":      {"169.254.169.254"},
		"mapped.test":    {"::ffff:10.0.0.5"},
		"mixed.test":     {"93.184.216.34", "10.0.0.5"},
		"cgnat.test":     {"100.64.0.9"},
	}
	addrs := []string{
		"127.0.0.1:80", "10.0.0.5:80", "169.254.169.254:80", "[fd00:ec2::254]:80",
		"[::1]:80", "100.64.0.1:80", "[::ffff:127.0.0.1]:80", "0.0.0.0:80",
		"localhost.test:80", "internal.test:80", "meta.test:80", "mapped.test:80",
		"mixed.test:80", "cgnat.test:80",
	}
	for _, addr := range addrs {
		t.Run(addr, func(t *testing.T) {
			g, dialed := fakeNet(zone, "127.0.0.1:1")
			_, err := g.DialContext(context.Background(), "tcp", addr)
			if !errors.Is(err, ErrBlockedDestination) {
				t.Fatalf("err = %v, want ErrBlockedDestination", err)
			}
			host, _, _ := net.SplitHostPort(addr)
			if !strings.Contains(err.Error(), host) {
				t.Fatalf("error %q should name the host %q", err, host)
			}
			if len(*dialed) != 0 {
				t.Fatalf("blocked destination was dialled: %v", *dialed)
			}
		})
	}
}

func TestDialContextAllowsPublicAndPinsResolvedIP(t *testing.T) {
	ln := listen(t)
	g, dialed := fakeNet(map[string][]string{"api.example.test": {"93.184.216.34"}}, ln.Addr().String())
	conn, err := g.DialContext(context.Background(), "tcp", "api.example.test:443")
	if err != nil {
		t.Fatalf("public destination refused: %v", err)
	}
	_ = conn.Close()
	if len(*dialed) != 1 || (*dialed)[0] != "93.184.216.34:443" {
		t.Fatalf("dialled %v, want the checked IP literal, not the name", *dialed)
	}
}

func TestDialContextAllowPrivateFlag(t *testing.T) {
	ln := listen(t)
	g, dialed := fakeNet(map[string][]string{"internal.test": {"10.0.0.5"}}, ln.Addr().String())
	g.AllowPrivate = func() bool { return true }
	for _, addr := range []string{"internal.test:80", "127.0.0.1:80", "169.254.169.254:80"} {
		conn, err := g.DialContext(context.Background(), "tcp", addr)
		if err != nil {
			t.Fatalf("%s refused with the escape hatch on: %v", addr, err)
		}
		_ = conn.Close()
	}
	if len(*dialed) != 3 {
		t.Fatalf("dialled %v, want 3 dials", *dialed)
	}
}

func TestDialContextAllowPrivateIsReadPerDial(t *testing.T) {
	var allow atomic.Bool
	g, _ := fakeNet(nil, listen(t).Addr().String())
	g.AllowPrivate = allow.Load
	if _, err := g.DialContext(context.Background(), "tcp", "10.0.0.1:80"); !errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("flag off: err = %v", err)
	}
	allow.Store(true)
	conn, err := g.DialContext(context.Background(), "tcp", "10.0.0.1:80")
	if err != nil {
		t.Fatalf("flag on: %v", err)
	}
	_ = conn.Close()
}

func TestDialContextResolverFailureIsNotABlock(t *testing.T) {
	g, _ := fakeNet(nil, "127.0.0.1:1")
	_, err := g.DialContext(context.Background(), "tcp", "nope.test:80")
	if err == nil || errors.Is(err, ErrBlockedDestination) {
		t.Fatalf("err = %v, want a plain resolver error", err)
	}
}

// TestRedirectToBlockedHostIsRefused proves the dial-time check also covers a
// redirect: the first hop is a "public" name (scripted to resolve to a public
// IP and routed to a local httptest server), whose response redirects to
// addresses the guard must refuse. The client follows redirects by default, so
// only the guard stands between the redirect and the internal target.
func TestRedirectToBlockedHostIsRefused(t *testing.T) {
	var internalHits atomic.Int32
	targets := []struct {
		name string
		host string
	}{
		{"literal loopback", "127.0.0.1:9"},
		{"literal metadata", "169.254.169.254"},
		{"literal rfc1918", "10.0.0.5:8080"},
		{"dns name resolving to rfc1918", "internal.test:8080"},
		{"ipv4-mapped ipv6 literal", "[::ffff:10.0.0.5]:8080"},
	}
	for _, tt := range targets {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/hop" {
					http.Redirect(w, r, "http://"+tt.host+"/secret", http.StatusFound)
					return
				}
				internalHits.Add(1)
			}))
			t.Cleanup(srv.Close)

			g, dialed := fakeNet(map[string][]string{
				"public.test":   {"93.184.216.34"},
				"internal.test": {"10.0.0.5"},
			}, strings.TrimPrefix(srv.URL, "http://"))
			client := &http.Client{
				Timeout:   5 * time.Second,
				Transport: &http.Transport{DialContext: g.DialContext},
			}
			_, err := client.Get("http://public.test/hop")
			if err == nil {
				t.Fatal("redirect to a blocked host was followed")
			}
			if !errors.Is(err, ErrBlockedDestination) {
				t.Fatalf("err = %v, want ErrBlockedDestination", err)
			}
			var uerr *url.Error
			if !errors.As(err, &uerr) {
				t.Fatalf("err = %T, want *url.Error", err)
			}
			if len(*dialed) != 1 {
				t.Fatalf("dialled %v, want only the first hop", *dialed)
			}
			if internalHits.Load() != 0 {
				t.Fatal("the redirect target was reached")
			}
		})
	}
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln
}
