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

package registry

import (
	"fmt"
	"net/textproto"
	"strings"
)

// ProviderOptionForwardClientHeaders is the provider_options key of an LLM
// registry listing the client request headers the gateway copies onto the
// request it sends the provider: traceparent and tracestate to join the
// caller's trace, a request id, a beta flag a client SDK sends. Nothing is
// forwarded unless it is listed; the gateway builds every provider request
// itself.
const ProviderOptionForwardClientHeaders = "forward_client_headers"

const maxForwardClientHeaders = 32

// unforwardableHeaders are never copied from a client to a provider, whatever
// a registry lists: credentials (the caller's gateway credential is not the
// provider's), headers that frame the message the gateway rewrites, and hop
// headers that belong to one connection.
var unforwardableHeaders = map[string]struct{}{
	"Authorization":        {},
	"Proxy-Authorization":  {},
	"Cookie":               {},
	"Set-Cookie":           {},
	"Host":                 {},
	"Content-Length":       {},
	"Content-Type":         {},
	"Content-Encoding":     {},
	"Accept-Encoding":      {},
	"Transfer-Encoding":    {},
	"Connection":           {},
	"Keep-Alive":           {},
	"Te":                   {},
	"Trailer":              {},
	"Upgrade":              {},
	"Expect":               {},
	"X-Api-Key":            {},
	"Api-Key":              {},
	"X-Goog-Api-Key":       {},
	"X-Amz-Security-Token": {},
}

// unforwardablePrefixes are the gateway's own headers.
var unforwardablePrefixes = []string{"X-Tg-", "X-Ag-"}

// ForwardClientHeaders returns the canonical header names an LLM registry's
// provider_options lists for forwarding, nil when it lists none. It reads a
// list as stored (strings, or values decoded from JSON) and skips anything
// that is not a forwardable header name, so a list stored before validation
// tightened can never forward a credential.
func ForwardClientHeaders(options map[string]any) []string {
	names, ok := forwardClientHeaderList(options)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(names))
	for _, name := range names {
		if canonical, err := forwardableHeader(name); err == nil {
			out = append(out, canonical)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// NormalizeForwardClientHeaders validates provider_options' forward list and
// rewrites it in place as canonical, de-duplicated names, dropping the key when
// the list is empty.
func NormalizeForwardClientHeaders(options map[string]any) error {
	if options == nil {
		return nil
	}
	raw, exists := options[ProviderOptionForwardClientHeaders]
	if !exists {
		return nil
	}
	names, ok := forwardClientHeaderList(options)
	if !ok {
		return fmt.Errorf("%w: provider_options.%s must be a list of header names, got %T", ErrInvalidRegistry, ProviderOptionForwardClientHeaders, raw)
	}
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, name := range names {
		if strings.TrimSpace(name) == "" {
			continue
		}
		canonical, err := forwardableHeader(name)
		if err != nil {
			return err
		}
		if _, dup := seen[canonical]; dup {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	if len(out) > maxForwardClientHeaders {
		return fmt.Errorf("%w: provider_options.%s lists %d headers, at most %d", ErrInvalidRegistry, ProviderOptionForwardClientHeaders, len(out), maxForwardClientHeaders)
	}
	if len(out) == 0 {
		delete(options, ProviderOptionForwardClientHeaders)
		return nil
	}
	options[ProviderOptionForwardClientHeaders] = out
	return nil
}

func forwardClientHeaderList(options map[string]any) ([]string, bool) {
	if options == nil {
		return nil, false
	}
	switch v := options[ProviderOptionForwardClientHeaders].(type) {
	case nil:
		return nil, false
	case []string:
		return v, true
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	default:
		return nil, false
	}
}

func forwardableHeader(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 || !isHeaderToken(name) {
		return "", fmt.Errorf("%w: provider_options.%s: %q is not a header name", ErrInvalidRegistry, ProviderOptionForwardClientHeaders, name)
	}
	canonical := textproto.CanonicalMIMEHeaderKey(name)
	if _, refused := unforwardableHeaders[canonical]; refused {
		return "", fmt.Errorf("%w: provider_options.%s: %s is never forwarded to a provider", ErrInvalidRegistry, ProviderOptionForwardClientHeaders, canonical)
	}
	for _, prefix := range unforwardablePrefixes {
		if strings.HasPrefix(canonical, prefix) {
			return "", fmt.Errorf("%w: provider_options.%s: %s is a gateway header and is never forwarded", ErrInvalidRegistry, ProviderOptionForwardClientHeaders, canonical)
		}
	}
	return canonical, nil
}

// isHeaderToken reports whether name is an RFC 9110 field-name token.
func isHeaderToken(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}
