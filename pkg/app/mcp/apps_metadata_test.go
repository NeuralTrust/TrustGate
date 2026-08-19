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
	"errors"
	"strings"
	"testing"
)

func TestAppsMetadataValidation(t *testing.T) {
	for _, uri := range []string{"ui://widget", "ui://tenant.internal/view", "ui://nip.io/view", "ui://widget.example", "ui://xn--bcher-kva.example/a/b-._~9"} {
		got, err := ValidateAppsURI(uri)
		requireApps(t, err == nil && got == uri)
	}
	invalid := []string{"UI://widget", "ui://", "ui://LOCALHOST", "ui://localhost", "ui://api.localhost", "ui://127.0.0.1", "ui://2130706433", "ui://017700000001", "ui://0x7f000001", "ui://[::1]", "ui://user@host.example", "ui://host.example:444", "ui://host.example/", "ui://host.example/a//b",
		"ui://host.example/.", "ui://host.example/..", "ui://host.example/a?b", "ui://host.example/a#b", "ui://host.example/a%20b", "ui://host.example/a\\b", "ui://host.example/a b", "ui://host.example/...", "ui://host.example/A", "ui://host_example", "ui://Host.example", "ui://host.example/é", "ui://host.example/\x01"}
	invalid = append(invalid, "ui://host.example/"+strings.Repeat("a/", maxAppsPathSegments+1), "ui://host.example/"+strings.Repeat("a", maxAppsURIBytes))
	for _, uri := range invalid {
		_, err := ValidateAppsURI(uri)
		requireApps(t, err != nil)
	}
	_, err := ValidateAppsURI("ui://host.example/%secret")
	requireAppsError(t, err, AppsMetadataURIReason, "ui://host.example/%secret")
	reject := func(per, total int, origins, permissions []string) {
		_, err := NewAppsMetadataPolicy(per, total, origins, permissions)
		requireAppsError(t, err, AppsMetadataPolicyReason, strings.Join(origins, ","))
	}
	for _, limits := range [][2]int{{0, 1}, {1, 0}, {2, 1}, {1, 65}} {
		reject(limits[0], limits[1], nil, nil)
	}
	reject(1, 1, []string{"https://a.example.com", "https://b.example.com"}, nil)
	reject(2, 2, []string{"https://a.example.com", "https://a.example.com"}, nil)
	reject(1, 1, nil, []string{"camera", "camera"})
	reject(1, 1, nil, []string{"usb"})
	reject(1, 1, nil, []string{"camera", "microphone", "geolocation", "clipboardWrite", "usb"})
	for _, origin := range []string{"https://*.example.com", "https://2130706433", "https://0177.0.0.1", "https://127.0.0.1.nip.io", "https://app.github.io", "https://service.internal", "https://example.com:443", "https://example.com:0443", "https://example.com:0", "https://example.com:65536", "https://user@example.com", "HTTPS://example.com", "https://" + strings.Repeat("a", maxAppsOriginBytes)} {
		reject(1, 1, []string{origin}, nil)
	}
	input := map[string]any{"ui": map[string]any{"resourceUri": "ui://widget/a"}, "ui/resourceUri": "ui://widget/a", "opaque": 7}
	got, err := ParseToolAppsMetadata(input)
	requireApps(t, err == nil && got.ResourceURI == "ui://widget/a" && got.HasCanonicalURI && got.HasDeprecatedURI && got.ModelVisible && got.ApplicationVisible && input["opaque"] == 7 && input["ui/resourceUri"] == "ui://widget/a" && input["ui"].(map[string]any)["resourceUri"] == "ui://widget/a")
	appOnly, err := ParseToolAppsMetadata(map[string]any{"ui": map[string]any{"visibility": []any{"app"}}})
	requireApps(t, err == nil && appOnly.ResourceURI == "" && !appOnly.ModelVisible && appOnly.ApplicationVisible && !appOnly.HasCanonicalURI && !appOnly.HasDeprecatedURI)
	canonical, canonicalErr := ParseToolAppsMetadata(map[string]any{"ui": map[string]any{"resourceUri": "ui://widget"}})
	deprecated, deprecatedErr := ParseToolAppsMetadata(map[string]any{"ui/resourceUri": "ui://widget"})
	requireApps(t, canonicalErr == nil && deprecatedErr == nil && canonical.HasCanonicalURI && !canonical.HasDeprecatedURI && !deprecated.HasCanonicalURI && deprecated.HasDeprecatedURI)
	oversized := map[string]any{}
	for i := 0; i <= maxAppsMetadataFields; i++ {
		oversized[strings.Repeat("x", i+1)] = nil
	}
	for _, meta := range map[string]map[string]any{
		"conflict": {"ui": map[string]any{"resourceUri": "ui://one"}, "ui/resourceUri": "ui://two"}, "non-string": {"ui/resourceUri": 1}, "unknown UI": {"ui": map[string]any{"resourceUri": "ui://one", "x": true}},
		"unknown legacy UI": {"ui/resourceUri": "ui://one", "ui/x": true}, "empty visibility": {"ui": map[string]any{"resourceUri": "ui://one", "visibility": []any{}}}, "duplicate visibility": {"ui": map[string]any{"resourceUri": "ui://one", "visibility": []any{"app", "app"}}},
		"unknown visibility": {"ui": map[string]any{"resourceUri": "ui://one", "visibility": []any{"host"}}}, "too much visibility": {"ui": map[string]any{"visibility": []any{"model", "app", "model"}}}, "oversized URI": {"ui/resourceUri": "ui://" + strings.Repeat("a", maxAppsURIBytes)},
		"too many UI fields": {"ui": map[string]any{"resourceUri": "ui://one", "visibility": []any{"app"}, "x": nil}}, "too many metadata fields": oversized, "long metadata key": {strings.Repeat("k", maxAppsMetadataKeyBytes+1): nil},
	} {
		_, err := ParseToolAppsMetadata(meta)
		requireAppsError(t, err, AppsMetadataToolReason, "ui://two")
	}
	_, err = ParseToolAppsMetadata(map[string]any{"ui/resourceUri": "ui://localhost"})
	requireAppsError(t, err, AppsMetadataURIReason, "ui://localhost")
	origins := []string{"https://cdn.example.com", "https://api.example.com:8443", "wss://socket.example.com:8443"}
	permissions := []string{"camera", "clipboardWrite"}
	policy, err := NewAppsMetadataPolicy(3, 5, origins, permissions)
	requireApps(t, err == nil)
	origins[0], permissions[0] = "https://changed.example.com", "microphone"
	validResource := map[string]any{"csp": map[string]any{"connectDomains": []any{"https://api.example.com:8443", "wss://socket.example.com:8443"}, "resourceDomains": []any{"https://cdn.example.com"}}, "permissions": map[string]any{"camera": map[string]any{}, "clipboardWrite": map[string]any{}}, "prefersBorder": true}
	for _, raw := range []any{validResource, map[string]any{}, map[string]any{"csp": map[string]any{}}} {
		requireApps(t, ValidateResourceAppsMetadata(raw, policy) == nil)
	}
	for name, raw := range map[string]any{
		"non-object": 7, "unknown UI": map[string]any{"x": true}, "host domain intentionally forbidden": map[string]any{"domain": "app.example.com"},
		"border": map[string]any{"prefersBorder": "yes"}, "unknown CSP": map[string]any{"csp": map[string]any{"scriptDomains": []any{}}}, "wss resource": map[string]any{"csp": map[string]any{"resourceDomains": []any{"wss://socket.example.com:8443"}}},
		"duplicate": map[string]any{"csp": map[string]any{"resourceDomains": []any{"https://cdn.example.com", "https://cdn.example.com"}}}, "not allowed": map[string]any{"csp": map[string]any{"resourceDomains": []any{"https://other.example.com"}}}, "unknown permission": map[string]any{"permissions": map[string]any{"usb": map[string]any{}}},
		"denied permission": map[string]any{"permissions": map[string]any{"microphone": map[string]any{}}}, "too many resource fields": map[string]any{"csp": map[string]any{}, "permissions": map[string]any{}, "prefersBorder": true, "domain": nil, "x": nil},
		"too many CSP fields": map[string]any{"csp": map[string]any{"connectDomains": []any{}, "resourceDomains": []any{}, "frameDomains": []any{}, "baseUriDomains": []any{}, "x": []any{}}}, "too many permissions": map[string]any{"permissions": map[string]any{"camera": map[string]any{}, "microphone": map[string]any{}, "geolocation": map[string]any{}, "clipboardWrite": map[string]any{}, "usb": map[string]any{}}},
	} {
		requireAppsError(t, ValidateResourceAppsMetadata(raw, policy), AppsMetadataResourceReason, name)
	}
	requireAppsError(t, ValidateResourceAppsMetadata(map[string]any{"permissions": map[string]any{"camera": map[string]any{"secret": "front-camera-secret"}}}, policy), AppsMetadataResourceReason, "front-camera-secret")
	bounded, _ := NewAppsMetadataPolicy(1, 2, []string{"https://cdn.example.com", "https://api.example.com:8443"}, nil)
	for _, csp := range []any{map[string]any{"resourceDomains": []any{"https://cdn.example.com", "https://api.example.com:8443"}}, map[string]any{"resourceDomains": []any{"https://cdn.example.com"}, "frameDomains": []any{"https://api.example.com:8443"}, "baseUriDomains": []any{"https://cdn.example.com"}}} {
		requireAppsError(t, ValidateResourceAppsMetadata(map[string]any{"csp": csp}, bounded), AppsMetadataResourceReason, "")
	}
	listing := map[string]any{"ui": map[string]any{"prefersBorder": true}}
	content := map[string]any{"ui": map[string]any{}}
	selected, ok := SelectResourceAppsMetadata(listing, content)
	ui, valid := selected.(map[string]any)
	requireApps(t, ok && valid && len(ui) == 0)
	selected, ok = SelectResourceAppsMetadata(listing, nil)
	ui, valid = selected.(map[string]any)
	requireApps(t, ok && valid && ui["prefersBorder"] == true)
	_, ok = SelectResourceAppsMetadata(nil, nil)
	requireApps(t, !ok)
	selected, _ = SelectResourceAppsMetadata(nil, map[string]any{"ui": map[string]any{"domain": "app.example.com"}})
	requireAppsError(t, ValidateResourceAppsMetadata(selected, AppsMetadataPolicy{}), AppsMetadataResourceReason, "app.example.com")
}
func requireAppsError(t *testing.T, err error, reason AppsMetadataReason, secret string) {
	var typed *AppsMetadataError
	requireApps(t, errors.Is(err, ErrInvalidAppsMetadata) && errors.As(err, &typed) && typed.Reason == reason && (secret == "" || !strings.Contains(err.Error(), secret)))
}
func requireApps(t *testing.T, valid bool) {
	if !valid {
		t.FailNow()
	}
}
