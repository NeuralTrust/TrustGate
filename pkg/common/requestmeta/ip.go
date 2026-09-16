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
	"slices"
	"strings"
)

func NewIPResolver(mode string, trustedProxyCIDRs []netip.Prefix) func(string, string) string {
	trusted := slices.Clone(trustedProxyCIDRs)
	return func(peer, forwardedFor string) string {
		address, err := netip.ParseAddr(peer)
		if hostPort, parseErr := netip.ParseAddrPort(peer); parseErr == nil {
			address, err = hostPort.Addr(), nil
		}
		if err != nil {
			return ""
		}
		address = address.Unmap()
		fallback := address.String()
		if mode != "gcp" || !slices.ContainsFunc(trusted, func(prefix netip.Prefix) bool { return prefix.Contains(address) }) {
			return fallback
		}
		if len(forwardedFor) > 4096 || strings.Count(forwardedFor, ",") >= 32 || strings.ContainsAny(forwardedFor, "\r\n") {
			return fallback
		}
		cut := strings.LastIndexByte(forwardedFor, ',')
		if cut < 0 {
			return fallback
		}
		frontend, err := netip.ParseAddr(strings.TrimSpace(forwardedFor[cut+1:]))
		if err != nil || !validForwardedIP(frontend) {
			return fallback
		}
		clientPart := forwardedFor[:cut]
		clientPart = clientPart[strings.LastIndexByte(clientPart, ',')+1:]
		client, err := netip.ParseAddr(strings.TrimSpace(clientPart))
		if err != nil || !validForwardedIP(client) {
			return fallback
		}
		return client.Unmap().String()
	}
}

func validForwardedIP(address netip.Addr) bool {
	return address.Zone() == "" && !address.IsUnspecified() && !address.IsMulticast()
}
