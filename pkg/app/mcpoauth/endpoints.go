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

// SharedClientQuery describes the auth of one registry asking for the
// platform's shared OAuth client.
type SharedClientQuery struct {
	// Code is the registry's catalog code; Provider stands in for it when it
	// is empty.
	Code     string
	Provider string
	// ClientID is the client id stored on the registry.
	ClientID     string
	AuthorizeURL string
	TokenURL     string
	// Strict is for a configuration that goes out as is (a compiled snapshot,
	// a discovered endpoint pair): both endpoints must be set and on the
	// provider's hosts, and ClientID must be the shared client's id. Otherwise
	// an empty endpoint (resolved later) and an empty ClientID are accepted.
	Strict bool
}

// SharedCode returns the catalog code a shared client is looked up by: code,
// or provider when code is empty.
func SharedCode(code, provider string) string {
	if c := strings.TrimSpace(code); c != "" {
		return c
	}
	return strings.TrimSpace(provider)
}

// SharedClientFor returns the platform's shared OAuth client when q may use
// it: the provider serves q's code, q's client id is the shared one (or empty,
// unless Strict), and q's endpoints are the provider's own (see
// UsesProviderEndpoints and Strict). Every place that hands out or stores the
// shared client decides with this one predicate.
func SharedClientFor(p Provider, q SharedClientQuery) (Credentials, bool) {
	if p == nil {
		return Credentials{}, false
	}
	code := SharedCode(q.Code, q.Provider)
	creds, ok := p.CredentialsFor(code)
	if !ok {
		return Credentials{}, false
	}
	id := strings.TrimSpace(q.ClientID)
	if (id != "" || q.Strict) && id != creds.ClientID {
		return Credentials{}, false
	}
	if q.Strict && (strings.TrimSpace(q.AuthorizeURL) == "" || strings.TrimSpace(q.TokenURL) == "") {
		return Credentials{}, false
	}
	given := strings.TrimSpace(q.AuthorizeURL) != "" || strings.TrimSpace(q.TokenURL) != ""
	if (q.Strict || given) && !UsesProviderEndpoints(code, q.AuthorizeURL, q.TokenURL) {
		return Credentials{}, false
	}
	return creds, true
}

// ProviderFunc adapts a lookup function to Provider.
type ProviderFunc func(code string) (Credentials, bool)

// CredentialsFor calls f.
func (f ProviderFunc) CredentialsFor(code string) (Credentials, bool) { return f(code) }
