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
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

const (
	maxAuthBindingEntries     = 100
	maxAuthBindingEntryLength = 256

	maxClaimRules          = 32
	maxClaimNameLength     = 128
	maxClaimValuesPerClaim = 32
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
	// RequiredClaims are claims a bearer token must carry to enter. A claim
	// with values must hold one of them (a string claim equal to one, or an
	// array claim with one among its elements); a claim with none only has to
	// be there. This is how a route takes only workload tokens, say Entra's
	// idtyp=app, from an IdP that also issues tokens to people.
	RequiredClaims map[string][]string `json:"required_claims,omitempty"`
	// ForbiddenClaims are claims a bearer token must not carry: a token with
	// any of them, holding anything but an empty value, is refused. A route for
	// agents lists the claims only a person's token has (email, upn, name,
	// preferred_username) so a token minted for someone at a keyboard cannot be
	// replayed by an agent.
	ForbiddenClaims []string `json:"forbidden_claims,omitempty"`
}

// Normalize trims, drops empties and de-duplicates every list, keeping order.
// A required claim keeps its trimmed name and normalized values; one whose
// name is blank is dropped.
func (b *AuthBinding) Normalize() {
	if b == nil {
		return
	}
	b.AllowedClientIDs = normalizeList(b.AllowedClientIDs)
	b.AllowedCertificateSubjects = normalizeList(b.AllowedCertificateSubjects)
	b.ForbiddenClaims = normalizeList(b.ForbiddenClaims)
	if len(b.RequiredClaims) == 0 {
		b.RequiredClaims = nil
		return
	}
	required := make(map[string][]string, len(b.RequiredClaims))
	for name, values := range b.RequiredClaims {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		required[name] = append(required[name], values...)
	}
	for name, values := range required {
		required[name] = normalizeList(values)
	}
	if len(required) == 0 {
		required = nil
	}
	b.RequiredClaims = required
}

// Validate bounds every list and checks claim names.
func (b AuthBinding) Validate() error {
	if err := validateBindingList(b.AllowedClientIDs, "allowed_client_ids"); err != nil {
		return err
	}
	if err := validateBindingList(b.AllowedCertificateSubjects, "allowed_certificate_subjects"); err != nil {
		return err
	}
	if len(b.ForbiddenClaims) > maxClaimRules {
		return fmt.Errorf("%w: forbidden_claims has %d entries, at most %d", ErrInvalidAuthBinding, len(b.ForbiddenClaims), maxClaimRules)
	}
	for _, name := range b.ForbiddenClaims {
		if err := validateClaimName(name, "forbidden_claims"); err != nil {
			return err
		}
	}
	if len(b.RequiredClaims) > maxClaimRules {
		return fmt.Errorf("%w: required_claims has %d entries, at most %d", ErrInvalidAuthBinding, len(b.RequiredClaims), maxClaimRules)
	}
	for _, name := range slices.Sorted(maps.Keys(b.RequiredClaims)) {
		if err := validateClaimName(name, "required_claims"); err != nil {
			return err
		}
		values := b.RequiredClaims[name]
		if len(values) > maxClaimValuesPerClaim {
			return fmt.Errorf("%w: required_claims.%s has %d values, at most %d", ErrInvalidAuthBinding, name, len(values), maxClaimValuesPerClaim)
		}
		for _, v := range values {
			if len(v) > maxAuthBindingEntryLength {
				return fmt.Errorf("%w: required_claims.%s value longer than %d characters", ErrInvalidAuthBinding, name, maxAuthBindingEntryLength)
			}
		}
		if slices.Contains(b.ForbiddenClaims, name) {
			return fmt.Errorf("%w: claim %q is both required and forbidden", ErrInvalidAuthBinding, name)
		}
	}
	return nil
}

func validateClaimName(name, field string) error {
	if name == "" || len(name) > maxClaimNameLength {
		return fmt.Errorf("%w: %s claim names must be 1 to %d characters", ErrInvalidAuthBinding, field, maxClaimNameLength)
	}
	if strings.IndexFunc(name, unicode.IsSpace) >= 0 {
		return fmt.Errorf("%w: %s claim name %q contains whitespace", ErrInvalidAuthBinding, field, name)
	}
	return nil
}

// IsZero reports whether the binding narrows nothing.
func (b AuthBinding) IsZero() bool {
	return len(b.AllowedClientIDs) == 0 && len(b.AllowedCertificateSubjects) == 0 &&
		len(b.RequiredClaims) == 0 && len(b.ForbiddenClaims) == 0
}

// AllowsToken reports whether a verified bearer token may enter: it names an
// allowed client and passes the claim rules.
func (b AuthBinding) AllowsToken(claims map[string]any) bool {
	return b.AllowsClient(claims) && b.AllowsClaims(claims)
}

// AllowsClaims applies RequiredClaims and ForbiddenClaims to a verified
// token's claims. With neither set every token passes.
func (b AuthBinding) AllowsClaims(claims map[string]any) bool {
	for _, name := range b.ForbiddenClaims {
		if claimPresent(claims[name]) {
			return false
		}
	}
	for name, accepted := range b.RequiredClaims {
		value, ok := claims[name]
		if !ok || !claimPresent(value) {
			return false
		}
		if len(accepted) == 0 {
			continue
		}
		if !slices.ContainsFunc(claimStrings(value), func(v string) bool { return slices.Contains(accepted, v) }) {
			return false
		}
	}
	return true
}

// claimPresent reports whether a claim holds something: not null, not an
// empty string and not an empty array. An IdP that sends "email": "" has not
// told anyone who the caller is.
func claimPresent(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(v) != ""
	case []any:
		return len(v) > 0
	case []string:
		return len(v) > 0
	default:
		return true
	}
}

// claimStrings is a claim's value as the strings a rule compares with: a
// string as itself, a boolean or a number in its JSON spelling, and an array
// as its elements of those kinds. Objects never match.
func claimStrings(value any) []string {
	switch v := value.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := claimScalar(item); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	default:
		if s, ok := claimScalar(v); ok {
			return []string{s}
		}
		return nil
	}
}

func claimScalar(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case bool:
		return strconv.FormatBool(v), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case int:
		return strconv.Itoa(v), true
	case int64:
		return strconv.FormatInt(v, 10), true
	case fmt.Stringer:
		// json.Number, when a decoder was told to keep numbers as written.
		return v.String(), true
	default:
		return "", false
	}
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

// AllowsCertificateClaims applies AllowsCertificate to the claims an mTLS
// principal carries (common_name, dns_names).
func (b AuthBinding) AllowsCertificateClaims(claims map[string]any) bool {
	if len(b.AllowedCertificateSubjects) == 0 {
		return true
	}
	commonName, _ := claims["common_name"].(string)
	var dnsNames []string
	switch v := claims["dns_names"].(type) {
	case []string:
		dnsNames = v
	case []any:
		for _, item := range v {
			if name, ok := item.(string); ok {
				dnsNames = append(dnsNames, name)
			}
		}
	}
	return b.AllowsCertificate(commonName, dnsNames)
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
