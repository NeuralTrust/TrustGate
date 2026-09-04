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
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// urlTemplateToken matches one {name} placeholder in a URL template. Names are
// restricted to word characters so a template can never smuggle regex or URL
// metacharacters through the placeholder syntax itself.
var urlTemplateToken = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`)

// safeURLSegment guards a value that will be substituted into a host or path
// segment (In != "query"). It is a deliberately strict allow-list — a DNS-label
// / identifier charset — so a per-user value can never inject URL structure
// (`/ : @ ? # %`, spaces, control characters) and repoint the shared registry's
// upstream to another host or path. Query values are percent-escaped instead and
// do not go through this check.
var safeURLSegment = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$`)

// ErrURLTemplate is the base for URL-template resolution and validation errors.
var ErrURLTemplate = fmt.Errorf("registry: url template")

// urlVariableVaultPrefix namespaces a secret URL variable's per-user value in the
// vault, keeping it distinct from OAuth/forwarded provider credentials (keyed by
// the bare catalog code). Both the writer (the configure flow) and the reader
// (the dial-time resolver) derive the key through URLVariableVaultProvider so
// they always agree.
const urlVariableVaultPrefix = "urlvar:"

// URLVariableVaultProvider is the vault "provider" key under which a secret URL
// variable's per-user value is stored, e.g. urlvar:com.brightdata/mcp:token.
func URLVariableVaultProvider(code, name string) string {
	return urlVariableVaultPrefix + strings.TrimSpace(code) + ":" + strings.TrimSpace(name)
}

// TemplateVariableNames returns the distinct placeholder names in a URL
// template, in first-appearance order. A template with no placeholders returns
// nil — the common (fully-determined URL) case.
func TemplateVariableNames(template string) []string {
	matches := urlTemplateToken.FindAllStringSubmatch(template, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		name := m[1]
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

// ValidateURLValues checks a principal's supplied values against a target's URL
// variable declaration, independent of dialing. It is the collection-time gate
// (install): every required variable must be present and non-empty; every
// non-query value must pass the structure-safe charset; unknown keys are
// rejected so a typo never silently no-ops. Secret and plain values are both
// validated here — only their storage differs (vault vs installation config).
func ValidateURLValues(vars []MCPURLVariable, values map[string]string) error {
	declared := make(map[string]MCPURLVariable, len(vars))
	for _, v := range vars {
		declared[v.Name] = v
	}
	for name := range values {
		if _, ok := declared[name]; !ok {
			return fmt.Errorf("%w: unknown variable %q", ErrURLTemplate, name)
		}
	}
	// Deterministic order so the first error is stable across runs.
	names := make([]string, 0, len(vars))
	for _, v := range vars {
		names = append(names, v.Name)
	}
	sort.Strings(names)
	for _, name := range names {
		v := declared[name]
		val, ok := values[name]
		val = strings.TrimSpace(val)
		if !ok || val == "" {
			if v.Required {
				return fmt.Errorf("%w: missing required variable %q", ErrURLTemplate, name)
			}
			continue
		}
		if err := validateValue(v, val); err != nil {
			return err
		}
	}
	return nil
}

// ResolveURL substitutes a principal's values into a URL template and returns the
// concrete upstream URL. A template with no placeholders is returned unchanged,
// so the dial path can call it unconditionally. Non-query values are validated to
// the structure-safe charset and substituted verbatim; query values are
// percent-escaped. Every placeholder present in the template must have a value
// (missing → error), and the result must parse as an http(s) URL with a host, so
// a partially-filled template can never dial a malformed or unexpected target.
func ResolveURL(template string, vars []MCPURLVariable, values map[string]string) (string, error) {
	tokens := TemplateVariableNames(template)
	if len(tokens) == 0 {
		return template, nil
	}
	declared := make(map[string]MCPURLVariable, len(vars))
	for _, v := range vars {
		declared[v.Name] = v
	}
	var resolveErr error
	resolved := urlTemplateToken.ReplaceAllStringFunc(template, func(match string) string {
		if resolveErr != nil {
			return match
		}
		name := match[1 : len(match)-1] // strip { }
		val := strings.TrimSpace(values[name])
		if val == "" {
			resolveErr = fmt.Errorf("%w: no value for variable %q", ErrURLTemplate, name)
			return match
		}
		v := declared[name] // zero value (In=="") when undeclared: treated as a segment
		if err := validateValue(v, val); err != nil {
			resolveErr = err
			return match
		}
		if v.In == URLVariableInQuery {
			return url.QueryEscape(val)
		}
		return val
	})
	if resolveErr != nil {
		return "", resolveErr
	}
	parsed, err := url.Parse(resolved)
	if err != nil {
		return "", fmt.Errorf("%w: resolved url is invalid: %w", ErrURLTemplate, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("%w: resolved url must be http(s), got %q", ErrURLTemplate, parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("%w: resolved url has no host", ErrURLTemplate)
	}
	return resolved, nil
}

// ValidateURLValue checks one supplied value against its variable declaration —
// the charset/structure rules, independent of whether it is required. The
// install path uses it to validate provided values while treating missing ones
// as "still needs configuration" rather than an error.
func ValidateURLValue(v MCPURLVariable, val string) error {
	return validateValue(v, val)
}

// validateValue enforces the per-position rules on one supplied value. Query
// values may hold arbitrary non-control text (they are percent-escaped at
// substitution); host/path values must pass the structure-safe charset and carry
// no ".." path-traversal sequence.
func validateValue(v MCPURLVariable, val string) error {
	if v.In == URLVariableInQuery {
		if strings.ContainsAny(val, "\x00\r\n") {
			return fmt.Errorf("%w: variable %q contains control characters", ErrURLTemplate, v.Name)
		}
		return nil
	}
	if strings.Contains(val, "..") {
		return fmt.Errorf("%w: variable %q must not contain %q", ErrURLTemplate, v.Name, "..")
	}
	if !safeURLSegment.MatchString(val) {
		return fmt.Errorf("%w: variable %q has an unsafe value; only letters, digits, '.', '-' and '_' are allowed", ErrURLTemplate, v.Name)
	}
	return nil
}
