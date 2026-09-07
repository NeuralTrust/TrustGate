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

package consumer

import (
	"fmt"
	"strings"
)

const (
	maxAuthBindingEntries     = 100
	maxAuthBindingEntryLength = 256
)

// AuthBinding narrows which callers of a shared trust anchor may enter this
// consumer. A gateway-level auth (an external IdP or an mTLS CA) is one anchor
// for many applications; without a binding, the only isolation between two
// applications of the same tenant is the token audience or the CA, which
// customers routinely share across a whole gateway. API keys need no binding:
// a key belongs to exactly one consumer.
type AuthBinding struct {
	// AllowedClientIDs are the azp / client_id claim values accepted on a
	// bearer JWT. Empty accepts any client the auth verifies.
	AllowedClientIDs []string `json:"allowed_client_ids,omitempty"`
	// AllowedCertificateSubjects are the client-certificate common names or
	// SAN DNS names accepted over mTLS. Empty accepts any certificate the auth's
	// CA verifies.
	AllowedCertificateSubjects []string `json:"allowed_certificate_subjects,omitempty"`
}

// Normalize trims, drops empties and de-duplicates both lists, keeping order.
func (b *AuthBinding) Normalize() {
	if b == nil {
		return
	}
	b.AllowedClientIDs = normalizeList(b.AllowedClientIDs)
	b.AllowedCertificateSubjects = normalizeList(b.AllowedCertificateSubjects)
}

// Validate bounds both lists.
func (b AuthBinding) Validate() error {
	if err := validateBindingList(b.AllowedClientIDs, "allowed_client_ids"); err != nil {
		return err
	}
	return validateBindingList(b.AllowedCertificateSubjects, "allowed_certificate_subjects")
}

// IsZero reports whether the binding narrows nothing.
func (b AuthBinding) IsZero() bool {
	return len(b.AllowedClientIDs) == 0 && len(b.AllowedCertificateSubjects) == 0
}

// AllowsClient reports whether a verified token's claims name an allowed
// client. The client is the azp claim, else client_id. With no allowed list
// every client passes; with one, a token that carries no client claim fails.
func (b AuthBinding) AllowsClient(claims map[string]any) bool {
	if len(b.AllowedClientIDs) == 0 {
		return true
	}
	client := clientOf(claims)
	if client == "" {
		return false
	}
	return containsString(b.AllowedClientIDs, client)
}

// AllowsCertificate reports whether a verified client certificate's common
// name or one of its SAN DNS names is allowed. With no allowed list every
// certificate the CA verified passes.
func (b AuthBinding) AllowsCertificate(commonName string, dnsNames []string) bool {
	if len(b.AllowedCertificateSubjects) == 0 {
		return true
	}
	if commonName != "" && containsString(b.AllowedCertificateSubjects, commonName) {
		return true
	}
	for _, name := range dnsNames {
		if name != "" && containsString(b.AllowedCertificateSubjects, name) {
			return true
		}
	}
	return false
}

// ClientOfClaims returns the client an access token was issued to: the azp
// claim, else client_id, else empty.
func ClientOfClaims(claims map[string]any) string {
	return clientOf(claims)
}

func clientOf(claims map[string]any) string {
	for _, key := range []string{"azp", "client_id"} {
		if v, ok := claims[key].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func normalizeList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func validateBindingList(list []string, field string) error {
	if len(list) > maxAuthBindingEntries {
		return fmt.Errorf("%w: %s has %d entries, at most %d", ErrInvalidAuthBinding, field, len(list), maxAuthBindingEntries)
	}
	for _, v := range list {
		if len(v) > maxAuthBindingEntryLength {
			return fmt.Errorf("%w: %s entry longer than %d characters", ErrInvalidAuthBinding, field, maxAuthBindingEntryLength)
		}
	}
	return nil
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
