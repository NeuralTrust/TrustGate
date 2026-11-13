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

// Package secretref is the grammar of secret references: strings such as
// secret://corp-vault/ai-gateway/openai#api_key that a credential field holds
// instead of the secret itself, and the fields allowed to hold one.
package secretref

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

// Scheme prefixes every reference. Matching is case-insensitive and ignores
// leading whitespace (see IsRef).
const Scheme = "secret://"

// MaxLength is the largest reference accepted, in bytes of the raw input.
const MaxLength = 1024

// ErrInvalidReference is returned for a value that looks like a reference but
// does not match the grammar. Such a value is never a literal.
var ErrInvalidReference = fmt.Errorf("invalid secret reference: %w", commonerrors.ErrValidation)

var storeNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// Ref is a parsed reference. Path, Field and Version hold decoded values;
// Store is lowercase.
type Ref struct {
	Store   string
	Path    string
	Field   string
	Version string
}

// IsRef reports whether s is reference-shaped: after leading whitespace, it
// starts with Scheme in any letter case. A reference-shaped value is never a
// literal credential: Parse either returns a Ref for it or an error, and no
// plane forwards it upstream.
func IsRef(s string) bool {
	s = strings.TrimLeft(s, " \t\r\n")
	return len(s) >= len(Scheme) && strings.EqualFold(s[:len(Scheme)], Scheme)
}

// ContainsRef reports whether s contains Scheme anywhere, in any letter case,
// such as "Bearer secret://…". Only a whole value can be a reference, so at a
// declared location such a value is refused rather than stored as a literal
// that would carry the reference upstream.
func ContainsRef(s string) bool {
	return strings.Contains(strings.ToLower(s), Scheme)
}

// ValidStoreName reports whether name, already lowercase, is a valid store
// name: 1-63 characters of [a-z0-9_-] starting with a letter or digit.
func ValidStoreName(name string) bool {
	return storeNamePattern.MatchString(name)
}

// Parse parses s. It returns ok=false and no error when s is a literal, and an
// error wrapping ErrInvalidReference when s is reference-shaped but malformed.
func Parse(s string) (Ref, bool, error) {
	if !IsRef(s) {
		return Ref{}, false, nil
	}
	ref, err := parse(s)
	if err != nil {
		return Ref{}, true, err
	}
	return ref, true, nil
}

func parse(s string) (Ref, error) {
	if len(s) > MaxLength {
		return Ref{}, fmt.Errorf("%w: longer than %d bytes", ErrInvalidReference, MaxLength)
	}
	if s != strings.TrimSpace(s) {
		return Ref{}, fmt.Errorf("%w: surrounding whitespace", ErrInvalidReference)
	}
	if !strings.HasPrefix(s, Scheme) {
		return Ref{}, fmt.Errorf("%w: the scheme must be written %q", ErrInvalidReference, Scheme)
	}
	rest := s[len(Scheme):]

	var ref Ref
	rest, rawField, hasField := strings.Cut(rest, "#")
	if hasField {
		if strings.ContainsAny(rawField, "?#") {
			return Ref{}, fmt.Errorf("%w: the field comes last: write ?version= before #field, and percent-encode ? and # inside it", ErrInvalidReference)
		}
		field, err := decodeComponent("field", rawField)
		if err != nil {
			return Ref{}, err
		}
		ref.Field = field
	}
	rest, rawQuery, hasQuery := strings.Cut(rest, "?")
	if hasQuery {
		version, err := parseQuery(rawQuery)
		if err != nil {
			return Ref{}, err
		}
		ref.Version = version
	}

	store, rawPath, hasPath := strings.Cut(rest, "/")
	store = strings.ToLower(store)
	if !ValidStoreName(store) {
		return Ref{}, fmt.Errorf("%w: the store must be 1-63 characters of [a-z0-9_-] starting with a letter or digit", ErrInvalidReference)
	}
	ref.Store = store
	if !hasPath || rawPath == "" {
		return Ref{}, fmt.Errorf("%w: the path is empty", ErrInvalidReference)
	}
	path, err := parsePath(rawPath)
	if err != nil {
		return Ref{}, err
	}
	ref.Path = path
	return ref, nil
}

func parseQuery(raw string) (string, error) {
	key, value, ok := strings.Cut(raw, "=")
	if !ok || key != "version" || strings.ContainsAny(value, "&;=") {
		return "", fmt.Errorf("%w: the only query parameter is version=<version>", ErrInvalidReference)
	}
	return decodeComponent("version", value)
}

func parsePath(raw string) (string, error) {
	segments := strings.Split(raw, "/")
	for i, segment := range segments {
		decoded, err := url.PathUnescape(segment)
		if err != nil {
			return "", fmt.Errorf("%w: path segment %d is not valid percent-encoding", ErrInvalidReference, i+1)
		}
		if decoded == "" || decoded == "." || decoded == ".." || strings.ContainsAny(decoded, "/\\") || hasControl(decoded) {
			return "", fmt.Errorf("%w: path segment %d must not be empty, \".\" or \"..\", nor contain \"/\", \"\\\" or a control character once decoded", ErrInvalidReference, i+1)
		}
		segments[i] = decoded
	}
	return strings.Join(segments, "/"), nil
}

func decodeComponent(name, raw string) (string, error) {
	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return "", fmt.Errorf("%w: the %s is not valid percent-encoding", ErrInvalidReference, name)
	}
	if decoded == "" || hasControl(decoded) {
		return "", fmt.Errorf("%w: the %s must not be empty or contain a control character", ErrInvalidReference, name)
	}
	return decoded, nil
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// Segments returns the decoded path segments.
func (r Ref) Segments() []string {
	return strings.Split(r.Path, "/")
}

// String returns the canonical form of r, which Parse turns back into r while
// it fits in MaxLength: percent-encoding can make it longer than the input.
func (r Ref) String() string {
	var b strings.Builder
	b.WriteString(Scheme)
	b.WriteString(r.Store)
	for _, segment := range r.Segments() {
		b.WriteByte('/')
		b.WriteString(url.PathEscape(segment))
	}
	if r.Version != "" {
		b.WriteString("?version=")
		b.WriteString(escapeComponent(r.Version))
	}
	if r.Field != "" {
		b.WriteByte('#')
		b.WriteString(escapeComponent(r.Field))
	}
	return b.String()
}

// escapeComponent escapes a version or field so that the separators the
// grammar splits on (#, ?, &, ;, =) never appear literally.
func escapeComponent(s string) string {
	escaped := url.PathEscape(s)
	return strings.NewReplacer("#", "%23", "?", "%3F", "&", "%26", ";", "%3B", "=", "%3D").Replace(escaped)
}

// PayloadKey identifies the payload a reference reads: references that differ
// only in Field share one fetch. NUL separates the parts because the grammar
// refuses control characters in every one of them.
func (r Ref) PayloadKey() string {
	return r.Store + "\x00" + r.Path + "\x00" + r.Version
}
