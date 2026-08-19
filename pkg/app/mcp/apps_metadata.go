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

package mcp

import (
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

const maxAppsURIBytes, maxAppsOriginBytes, maxAppsMetadataFields, maxAppsMetadataKeyBytes, maxAppsPathSegments, maxAppsPolicyEntries = 2048, 512, 64, 128, 32, 64

var (
	// ErrInvalidAppsMetadata identifies fail-closed MCP Apps metadata rejection.
	ErrInvalidAppsMetadata = &AppsMetadataError{}
	knownPermissions       = map[string]bool{"camera": true, "microphone": true, "geolocation": true, "clipboardWrite": true}
	cspDirectives          = map[string]bool{"connectDomains": true, "resourceDomains": false, "frameDomains": false, "baseUriDomains": false}
	dnsNamePattern         = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`)
	pathSegmentPattern     = regexp.MustCompile(`^[a-z0-9._~-]+$`)
	ipLikeHostPattern      = regexp.MustCompile(`^(?:0x[0-9a-f]+|[0-9]+)$|(?:^|\.)(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))+(?:\.|$)`)
	rebindHostPattern      = regexp.MustCompile(`(?:^|\.)(?:nip\.io|sslip\.io|xip\.io|localtest\.me|lvh\.me)$`)
)

// AppsMetadataReason is a bounded rejection category for protocol error mapping.
type AppsMetadataReason uint8

const AppsMetadataPolicyReason, AppsMetadataURIReason, AppsMetadataToolReason, AppsMetadataResourceReason AppsMetadataReason = 0, 1, 2, 3

// AppsMetadataError reports a bounded metadata rejection reason.
type AppsMetadataError struct{ Reason AppsMetadataReason }

func (e *AppsMetadataError) Error() string                { return "invalid MCP Apps metadata" }
func (e *AppsMetadataError) Is(target error) bool         { return target == ErrInvalidAppsMetadata }
func invalidAppsMetadata(reason AppsMetadataReason) error { return &AppsMetadataError{Reason: reason} }

// AppsMetadataPolicy is an immutable MCP Apps origin and permission policy.
type AppsMetadataPolicy struct {
	maxPerDirective, maxTotal int
	origins, permissions      map[string]bool
}

// NewAppsMetadataPolicy builds an independent, fail-closed metadata policy.
func NewAppsMetadataPolicy(maxPerDirective, maxTotal int, allowedOrigins, allowedPermissions []string) (AppsMetadataPolicy, error) {
	if maxPerDirective < 1 || maxTotal < maxPerDirective || maxTotal > maxAppsPolicyEntries ||
		len(allowedOrigins) > maxTotal || len(allowedPermissions) > len(knownPermissions) {
		return AppsMetadataPolicy{}, invalidAppsMetadata(AppsMetadataPolicyReason)
	}
	policy := AppsMetadataPolicy{maxPerDirective: maxPerDirective, maxTotal: maxTotal, origins: make(map[string]bool, len(allowedOrigins)), permissions: make(map[string]bool, len(allowedPermissions))}
	for _, origin := range allowedOrigins {
		if !validAppsOrigin(origin, true) || policy.origins[origin] {
			return AppsMetadataPolicy{}, invalidAppsMetadata(AppsMetadataPolicyReason)
		}
		policy.origins[origin] = true
	}
	for _, permission := range allowedPermissions {
		if policy.permissions[permission] || !knownPermissions[permission] {
			return AppsMetadataPolicy{}, invalidAppsMetadata(AppsMetadataPolicyReason)
		}
		policy.permissions[permission] = true
	}
	return policy, nil
}

// ValidateAppsURI validates a logical, non-network ui:// identifier and preserves it byte-for-byte.
func ValidateAppsURI(value string) (string, error) {
	if len(value) > maxAppsURIBytes || !strings.HasPrefix(value, "ui://") {
		return "", invalidAppsMetadata(AppsMetadataURIReason)
	}
	parts := strings.Split(strings.TrimPrefix(value, "ui://"), "/")
	if len(parts) == 0 || len(parts)-1 > maxAppsPathSegments || !validDNSName(parts[0], true) {
		return "", invalidAppsMetadata(AppsMetadataURIReason)
	}
	for _, segment := range parts[1:] {
		if strings.Trim(segment, ".") == "" || !pathSegmentPattern.MatchString(segment) {
			return "", invalidAppsMetadata(AppsMetadataURIReason)
		}
	}
	return value, nil
}

// ToolAppsMetadata is an immutable parsed tool UI declaration.
type ToolAppsMetadata struct {
	ResourceURI                                                         string
	HasCanonicalURI, HasDeprecatedURI, ModelVisible, ApplicationVisible bool
}

// ParseToolAppsMetadata validates tool _meta and returns its UI declaration.
func ParseToolAppsMetadata(meta map[string]any) (ToolAppsMetadata, error) {
	result := ToolAppsMetadata{ModelVisible: true, ApplicationVisible: true}
	if !validAppsKeys(meta, maxAppsMetadataFields) {
		return ToolAppsMetadata{}, invalidAppsMetadata(AppsMetadataToolReason)
	}
	if raw, present := meta["ui"]; present {
		ui, ok := raw.(map[string]any)
		if !ok || !validAppsKeys(ui, 2) {
			return ToolAppsMetadata{}, invalidAppsMetadata(AppsMetadataToolReason)
		}
		for key := range ui {
			if key != "resourceUri" && key != "visibility" {
				return ToolAppsMetadata{}, invalidAppsMetadata(AppsMetadataToolReason)
			}
		}
		if rawURI, ok := ui["resourceUri"]; ok {
			uri, valid := rawURI.(string)
			if !valid || len(uri) > maxAppsURIBytes {
				return ToolAppsMetadata{}, invalidAppsMetadata(AppsMetadataToolReason)
			}
			result.ResourceURI, result.HasCanonicalURI = uri, true
		}
		if rawVisibility, ok := ui["visibility"]; ok {
			model, app, err := parseAppsVisibility(rawVisibility)
			if err != nil {
				return ToolAppsMetadata{}, err
			}
			result.ModelVisible, result.ApplicationVisible = model, app
		}
	}
	for key := range meta {
		if strings.HasPrefix(key, "ui/") && key != "ui/resourceUri" {
			return ToolAppsMetadata{}, invalidAppsMetadata(AppsMetadataToolReason)
		}
	}
	if rawURI, ok := meta["ui/resourceUri"]; ok {
		uri, valid := rawURI.(string)
		if !valid || len(uri) > maxAppsURIBytes || result.HasCanonicalURI && uri != result.ResourceURI {
			return ToolAppsMetadata{}, invalidAppsMetadata(AppsMetadataToolReason)
		}
		result.ResourceURI, result.HasDeprecatedURI = uri, true
	}
	if result.HasCanonicalURI || result.HasDeprecatedURI {
		if _, err := ValidateAppsURI(result.ResourceURI); err != nil {
			return ToolAppsMetadata{}, err
		}
	}
	return result, nil
}
func parseAppsVisibility(raw any) (bool, bool, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 || len(values) > 2 {
		return false, false, invalidAppsMetadata(AppsMetadataToolReason)
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		visibility, valid := value.(string)
		if !valid || visibility != "model" && visibility != "app" || seen[visibility] {
			return false, false, invalidAppsMetadata(AppsMetadataToolReason)
		}
		seen[visibility] = true
	}
	return seen["model"], seen["app"], nil
}

// ValidateResourceAppsMetadata validates a resource _meta.ui value.
func ValidateResourceAppsMetadata(raw any, policy AppsMetadataPolicy) error {
	ui, ok := raw.(map[string]any)
	if !ok || !validAppsKeys(ui, 4) {
		return invalidAppsMetadata(AppsMetadataResourceReason)
	}
	for key, value := range ui {
		var err error
		switch key {
		case "domain":
			return invalidAppsMetadata(AppsMetadataResourceReason)
		case "prefersBorder":
			if _, valid := value.(bool); !valid {
				return invalidAppsMetadata(AppsMetadataResourceReason)
			}
		case "csp":
			err = validateAppsCSP(value, policy)
		case "permissions":
			err = validateAppsPermissions(value, policy)
		default:
			return invalidAppsMetadata(AppsMetadataResourceReason)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
func validateAppsCSP(raw any, policy AppsMetadataPolicy) error {
	csp, ok := raw.(map[string]any)
	if !ok || !validAppsKeys(csp, 4) {
		return invalidAppsMetadata(AppsMetadataResourceReason)
	}
	total := 0
	for directive, rawOrigins := range csp {
		allowWSS, known := cspDirectives[directive]
		origins, valid := rawOrigins.([]any)
		if !known || !valid {
			return invalidAppsMetadata(AppsMetadataResourceReason)
		}
		total += len(origins)
		if len(origins) > policy.maxPerDirective || total > policy.maxTotal {
			return invalidAppsMetadata(AppsMetadataResourceReason)
		}
		seen := make(map[string]bool, len(origins))
		for _, rawOrigin := range origins {
			origin, valid := rawOrigin.(string)
			if !valid || !validAppsOrigin(origin, allowWSS) || !policy.origins[origin] || seen[origin] {
				return invalidAppsMetadata(AppsMetadataResourceReason)
			}
			seen[origin] = true
		}
	}
	return nil
}
func validateAppsPermissions(raw any, policy AppsMetadataPolicy) error {
	permissions, ok := raw.(map[string]any)
	if !ok || !validAppsKeys(permissions, len(knownPermissions)) {
		return invalidAppsMetadata(AppsMetadataResourceReason)
	}
	for permission, rawValue := range permissions {
		value, object := rawValue.(map[string]any)
		if !object || len(value) != 0 || !policy.permissions[permission] {
			return invalidAppsMetadata(AppsMetadataResourceReason)
		}
	}
	return nil
}

// SelectResourceAppsMetadata applies content-item-over-listing UI precedence.
func SelectResourceAppsMetadata(listingMeta, contentMeta map[string]any) (any, bool) {
	if value, ok := contentMeta["ui"]; ok {
		return value, true
	}
	value, ok := listingMeta["ui"]
	return value, ok
}
func validAppsOrigin(origin string, allowWSS bool) bool {
	if len(origin) > maxAppsOriginBytes {
		return false
	}
	scheme, authority, ok := strings.Cut(origin, "://")
	if !ok || scheme != "https" && (!allowWSS || scheme != "wss") || authority == "" ||
		strings.ContainsAny(authority, "/?#@%\\*[] \t\r\n") {
		return false
	}
	host := authority
	if strings.Count(authority, ":") > 1 {
		return false
	}
	if before, after, found := strings.Cut(authority, ":"); found {
		host = before
		n, err := strconv.Atoi(after)
		if err != nil || n < 1 || n > 65535 || n == 443 || strconv.Itoa(n) != after {
			return false
		}
	}
	_, icann := publicsuffix.PublicSuffix(host)
	return icann && !rebindHostPattern.MatchString(host) && validDNSName(host, false)
}
func validDNSName(name string, singleLabel bool) bool {
	return name != "" && len(name) <= 253 && name != "localhost" && !strings.HasSuffix(name, ".localhost") && !ipLikeHostPattern.MatchString(name) && name == strings.ToLower(name) && (singleLabel || strings.Contains(name, ".")) && dnsNamePattern.MatchString(name)
}
func validAppsKeys(values map[string]any, maxFields int) bool {
	if len(values) > maxFields {
		return false
	}
	for key := range values {
		if len(key) > maxAppsMetadataKeyBytes {
			return false
		}
	}
	return true
}
