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

package checks

import (
	"regexp"
	"strings"

	"github.com/NeuralTrust/TrustGate/tools/nt-hooks/internal/gitx"
)

// DefaultHostAllow lists well-known internal names that are public knowledge.
var DefaultHostAllow = []string{"metadata.google.internal", "host.docker.internal"}

var internalHost = regexp.MustCompile(
	`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}` +
		`|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}` +
		`|192\.168\.\d{1,3}\.\d{1,3}` +
		`|[a-z0-9-]+(\.[a-z0-9-]+)*\.svc\.cluster\.local` +
		`|[a-z0-9-]+(\.[a-z0-9-]+)+\.internal)\b`)

// ScanInternalHosts reports private IPv4 addresses and cluster-internal host
// names in lines, ignoring the hosts in allow. Host names are matched in
// lowercase only, with at least two labels before .internal, so Go selectors
// such as codes.Internal or s.internal do not match.
func ScanInternalHosts(lines []gitx.Line, allow []string) []Finding {
	var out []Finding
	for _, l := range lines {
		if strings.Contains(l.Text, EscapeMarker) {
			continue
		}
		for _, m := range internalHost.FindAllString(l.Text, -1) {
			if allowedHost(m, allow) {
				continue
			}
			out = append(out, at(l, "internal address "+m+" in content"))
			break
		}
	}
	return out
}

func allowedHost(host string, allow []string) bool {
	for _, a := range allow {
		if host == a || strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}
