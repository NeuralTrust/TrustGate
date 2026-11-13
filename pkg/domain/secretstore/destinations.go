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

package secretstore

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// destinationPattern is a lowercase host name, or one that starts with "*."
// to match every host below it.
var destinationPattern = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// hostPattern is a lowercase host name.
var hostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9_-]*[a-z0-9])?)*$`)

// validateDestinations checks a store's allowed destinations: nil is absent
// and allows every host; a present list must not be empty, and every entry is
// a lowercase host name or "*." followed by one, with no scheme, port, path or
// trailing dot.
func validateDestinations(store string, destinations []string) error {
	if destinations == nil {
		return nil
	}
	if len(destinations) == 0 {
		return fmt.Errorf("%w: store %q: allowed_destinations must not be empty; leave it out to allow every host", ErrInvalidStore, store)
	}
	for _, d := range destinations {
		if !destinationPattern.MatchString(d) {
			return fmt.Errorf("%w: store %q: allowed destination %q must be a lowercase host such as api.openai.com or *.amazonaws.com", ErrInvalidStore, store, d)
		}
	}
	return nil
}

// NormalizeHost returns the comparable form of a host or URL: lowercase,
// without scheme, port, path or trailing dot. It returns "" for a value with
// no host, and for one that is not a host name or an IP address, such as a
// host built from a field that carries a path or fragment: it must never
// match an allowed suffix.
func NormalizeHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		raw = u.Host
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.TrimSuffix(strings.ToLower(strings.Trim(raw, "[]")), ".")
	if net.ParseIP(raw) == nil && !hostPattern.MatchString(raw) {
		return ""
	}
	return raw
}

func destinationMatches(pattern, host string) bool {
	if suffix, ok := strings.CutPrefix(pattern, "*"); ok {
		return strings.HasSuffix(host, suffix) && len(host) > len(suffix)
	}
	return host == pattern
}

// AllowsDestinations reports whether a value may be sent to every one of
// hosts. A store without allowed destinations allows any host. With them,
// every host must match one, and an empty hosts list (where the value goes
// could not be determined) is refused: the check fails closed.
func (s *Store) AllowsDestinations(hosts []string) error {
	if s.AllowedDestinations == nil {
		return nil
	}
	if len(hosts) == 0 {
		return fmt.Errorf("store %q: where the value is sent is unknown: %w", s.Name, ErrDestinationNotAllowed)
	}
	for _, h := range hosts {
		host := NormalizeHost(h)
		allowed := false
		for _, pattern := range s.AllowedDestinations {
			if host != "" && destinationMatches(pattern, host) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("store %q: host %q: %w", s.Name, host, ErrDestinationNotAllowed)
		}
	}
	return nil
}
