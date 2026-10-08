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

package mcpoauth

import (
	"net/url"
	"strings"
)

var googleOAuthHosts = map[string]struct{}{
	"accounts.google.com":   {},
	"oauth2.googleapis.com": {},
	"www.googleapis.com":    {},
}

// UsesProviderEndpoints reports whether a registry of catalog code talks to
// the provider's own authorization server: each of authorizeURL and tokenURL
// is either empty or an https URL on one of the provider's hosts. Only such a
// registry may be given the platform's shared OAuth client. It is false for a
// code no shared client serves.
func UsesProviderEndpoints(code, authorizeURL, tokenURL string) bool {
	switch strings.TrimSpace(code) {
	case GmailCode, CalendarCode, DriveCode:
		return onHosts(authorizeURL, googleOAuthHosts) && onHosts(tokenURL, googleOAuthHosts)
	default:
		return false
	}
}

func onHosts(raw string, hosts map[string]struct{}) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	if p := u.Port(); p != "" && p != "443" {
		return false
	}
	_, ok := hosts[strings.ToLower(u.Hostname())]
	return ok
}
