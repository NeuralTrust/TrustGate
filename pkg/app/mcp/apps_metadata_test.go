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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
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

func TestAppsListPolicyTools(t *testing.T) {
	metadata, err := NewAppsMetadataPolicy(1, 1, nil, nil)
	requireApps(t, err == nil)
	policy := NewAppsListPolicy(true, metadata)
	cases := []struct {
		name, raw string
		drop      bool
	}{
		{"absent", `{"name":"absent","description":"keep"}`, false},
		{"unrelated", `{"name":"unrelated","_meta":{"trace":{"id":1}}}`, false},
		{"scalar", `{"name":"scalar","_meta":7}`, false},
		{"canonical", `{"name":"canonical","_meta":{"ui":{"resourceUri":"ui://widget/canonical"}}}`, false},
		{"deprecated", `{"name":"deprecated","_meta":{"ui/resourceUri":"ui://widget/deprecated"}}`, false},
		{"conflict", `{"name":"conflict","_meta":{"ui":{"resourceUri":"ui://widget/a"},"ui/resourceUri":"ui://widget/b"}}`, true},
		{"wrong ui", `{"name":"wrong","_meta":{"ui":[]}}`, true},
		{"unknown ui prefix", `{"name":"unknown","_meta":{"ui/secret":true}}`, true},
		{"invalid URI", `{"name":"uri","_meta":{"ui":{"resourceUri":"ui://localhost"}}}`, true},
		{"duplicate key", `{"name":"duplicate","_meta":{"ui":{},"\u0075i":{}}}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := []Tool{mustAppsTool(t, tc.raw)}
			original := input[0].payload["_meta"]
			snapshot := append(json.RawMessage(nil), original...)
			got, outcome := policy.FilterTools(input)
			if tc.drop {
				requireApps(t, got != nil && len(got) == 0 && outcome.Dropped == 1 && bytes.Equal(input[0].payload["_meta"], snapshot))
				return
			}
			filtered := got[0].payload["_meta"]
			sameRaw := len(original) == 0 || &original[0] == &filtered[0]
			requireApps(t, len(got) == 1 && &got[0] == &input[0] && outcome.Dropped == 0 && sameRaw && bytes.Equal(filtered, snapshot))
		})
	}

	invalid := mustAppsTool(t, `{"name":"invalid","_meta":{"ui":"bad"}}`)
	disabledInput := []Tool{invalid}
	disabled, outcome := (AppsListPolicy{}).FilterTools(disabledInput)
	requireApps(t, &disabled[0] == &disabledInput[0] && outcome.Dropped == 0)

	mixed := []Tool{
		mustAppsTool(t, `{"name":"first","_meta":{"trace":1}}`),
		invalid,
		mustAppsTool(t, `{"name":"last","_meta":{"ui":{"resourceUri":"ui://widget/last"}}}`),
	}
	lastMeta := mixed[2].payload["_meta"]
	filtered, outcome := policy.FilterTools(mixed)
	requireApps(t, len(filtered) == 2 && filtered[0].Name == "first" && filtered[1].Name == "last" && outcome.Dropped == 1 && &lastMeta[0] == &filtered[1].payload["_meta"][0])
	allInvalid, outcome := policy.FilterTools([]Tool{invalid, mustAppsTool(t, `{"name":"other","_meta":{"ui/x":true}}`)})
	requireApps(t, allInvalid != nil && len(allInvalid) == 0 && outcome.Dropped == 2)
}

func TestAppsListPolicyResources(t *testing.T) {
	metadata, err := NewAppsMetadataPolicy(2, 2, []string{"https://cdn.example.com"}, []string{"camera"})
	requireApps(t, err == nil)
	policy := NewAppsListPolicy(true, metadata)
	cases := []struct {
		name, raw string
		drop      bool
	}{
		{"absent", `{"name":"absent","uri":"https://example.com"}`, false},
		{"unrelated", `{"name":"unrelated","uri":"https://example.com","_meta":{"trace":1}}`, false},
		{"scalar", `{"name":"scalar","uri":"https://example.com","_meta":null}`, false},
		{"tool-only prefix", `{"name":"legacy","uri":"https://example.com","_meta":{"ui/resourceUri":"ui://widget"}}`, false},
		{"empty ui", `{"name":"empty","uri":"ui://widget","_meta":{"ui":{}}}`, false},
		{"valid", `{"name":"valid","uri":"ui://widget/view","_meta":{"ui":{"csp":{"resourceDomains":["https://cdn.example.com"]},"permissions":{"camera":{}}}}}`, false},
		{"invalid URI", `{"name":"uri","uri":"https://example.com","_meta":{"ui":{}}}`, true},
		{"invalid CSP", `{"name":"csp","uri":"ui://widget","_meta":{"ui":{"csp":{"resourceDomains":["https://other.example.com"]}}}}`, true},
		{"invalid permission", `{"name":"permission","uri":"ui://widget","_meta":{"ui":{"permissions":{"microphone":{}}}}}`, true},
		{"invalid ui shape", `{"name":"shape","uri":"ui://widget","_meta":{"ui":[]}}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := []Resource{mustAppsResource(t, tc.raw)}
			original := input[0].payload["_meta"]
			snapshot := append(json.RawMessage(nil), original...)
			got, outcome := policy.FilterResources(input)
			if tc.drop {
				requireApps(t, got != nil && len(got) == 0 && outcome.Dropped == 1 && bytes.Equal(input[0].payload["_meta"], snapshot))
				return
			}
			filtered := got[0].payload["_meta"]
			sameRaw := len(original) == 0 || &original[0] == &filtered[0]
			requireApps(t, len(got) == 1 && &got[0] == &input[0] && outcome.Dropped == 0 && sameRaw && bytes.Equal(filtered, snapshot))
		})
	}
}

func TestAppsListPolicyBoundsObjectMetadata(t *testing.T) {
	metadata, err := NewAppsMetadataPolicy(1, 1, nil, nil)
	requireApps(t, err == nil)
	policy := NewAppsListPolicy(true, metadata)
	badUTF8 := append(json.RawMessage(`{"x":"`), 0xff)
	badUTF8 = append(badUTF8, []byte(`"}`)...)
	flood := strings.Repeat("0,", maxAppsJSONTokens)
	cases := []struct {
		name string
		raw  json.RawMessage
		drop bool
	}{
		{"nested ui is unrelated", json.RawMessage(`{"nested":{"ui":[]}}`), false},
		{"invalid UTF-8", badUTF8, true},
		{"malformed", json.RawMessage(`{"x":`), true},
		{"over depth", json.RawMessage(`{"x":` + strings.Repeat(`[`, maxAppsJSONDepth) + `0` + strings.Repeat(`]`, maxAppsJSONDepth) + `}`), true},
		{"over tokens", json.RawMessage(`{"x":[` + flood + `0]}`), true},
		{"marker after flood", json.RawMessage(`{"x":[` + flood + `0],"ui":{}}`), true},
		{"over bytes", json.RawMessage(`{"x":"` + strings.Repeat("a", maxAppsListMetadataBytes) + `"}`), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tools, toolOutcome := policy.FilterTools([]Tool{{Name: "tool", payload: map[string]json.RawMessage{"_meta": tc.raw}}})
			resources, resourceOutcome := policy.FilterResources([]Resource{{Name: "resource", URI: "ui://widget", payload: map[string]json.RawMessage{"_meta": tc.raw}}})
			if tc.drop {
				requireApps(t, tools != nil && len(tools) == 0 && toolOutcome.Dropped == 1 && resources != nil && len(resources) == 0 && resourceOutcome.Dropped == 1)
			} else {
				requireApps(t, len(tools) == 1 && toolOutcome.Dropped == 0 && len(resources) == 1 && resourceOutcome.Dropped == 0)
			}
		})
	}
}

func mustAppsTool(t *testing.T, raw string) Tool {
	t.Helper()
	var tool Tool
	requireApps(t, json.Unmarshal([]byte(raw), &tool) == nil)
	return tool
}

func mustAppsResource(t *testing.T, raw string) Resource {
	t.Helper()
	var resource Resource
	requireApps(t, json.Unmarshal([]byte(raw), &resource) == nil)
	return resource
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

func TestAppsDocumentValidation(t *testing.T) {
	textBody := "<escaped>\tcontent"
	for _, tc := range []struct {
		field, wire string
		body        []byte
		encoding    AppsDocumentEncoding
	}{
		{"text", textBody, []byte(textBody), AppsDocumentTextEncoding},
		{"blob", "aaaa", []byte{105, 166, 154}, AppsDocumentBlobEncoding},
		{"blob", "YQ==", []byte("a"), AppsDocumentBlobEncoding},
	} {
		raw := appsDocumentRaw(tc.field, tc.wire, `,"_meta":{"ui":{}}`)
		original := append(json.RawMessage(nil), raw...)
		got, err := decodeAppsDocument("ui://widget", minAppsDocumentBytes, raw)
		requireApps(t, err == nil && got.metadata.Encoding == tc.encoding && got.metadata.DecodedSize == len(tc.body) && bytes.Equal(got.body, tc.body) && bytes.Equal(raw, original))
		for i := range raw {
			raw[i] = 0
		}
		requireApps(t, bytes.Equal(got.body, tc.body))
	}
	for _, malformed := range []string{`"\u000g"`, `"\ud800"`, `"\ud800\u0041"`, `"\udc00"`} {
		_, _, err := decodeAppsJSONString([]byte(malformed), minAppsDocumentBytes)
		requireApps(t, err != nil)
	}
	boundary := strings.Repeat("<", minAppsDocumentBytes)
	for _, max := range []int{minAppsDocumentBytes, maxAppsDocumentBytes} {
		got, err := decodeAppsDocument("ui://widget", max, appsDocumentRaw("text", boundary, ""))
		requireApps(t, err == nil && len(got.body) == len(boundary))
	}
	deepMeta := strings.Repeat(`{"x":`, maxAppsJSONDepth+1) + "0" + strings.Repeat("}", maxAppsJSONDepth+1)
	invalidTopUTF8 := json.RawMessage(bytes.Replace([]byte(`{"_meta":{"x":"bad"},"contents":[]}`), []byte("bad"), []byte{0xff}, 1))
	invalidContentUTF8 := json.RawMessage(bytes.Replace([]byte(`{"contents":[{"uri":"ui://widget","mimeType":"text/html;profile=mcp-app","text":"x","_meta":{"x":"bad"}}]}`), []byte("bad"), []byte{0xff}, 1))
	tooManyTokens := json.RawMessage(`{"contents":[` + strings.Repeat("0,", maxAppsJSONTokens) + `0]}`)
	requireApps(t, validateAppsJSON(tooManyTokens) != nil)
	cases := []struct {
		raw    json.RawMessage
		max    int
		reason AppsDocumentReason
		secret string
	}{
		{json.RawMessage(`null`), minAppsDocumentBytes, AppsDocumentEnvelopeReason, ""}, {json.RawMessage(`{"contents":[]}`), minAppsDocumentBytes, AppsDocumentEnvelopeReason, ""}, {json.RawMessage(`{"contents":[{},{}]}`), minAppsDocumentBytes, AppsDocumentEnvelopeReason, ""},
		{json.RawMessage(`{"contents":[],"contents":[]}`), minAppsDocumentBytes, AppsDocumentEnvelopeReason, ""}, {json.RawMessage(`{"_meta":{"x":1,"x":2},"contents":[]}`), minAppsDocumentBytes, AppsDocumentEnvelopeReason, ""},
		{json.RawMessage(`{"contents":[{"uri":"ui://widget","\u0075ri":"ui://widget","mimeType":"text/html;profile=mcp-app","text":"x"}]}`), minAppsDocumentBytes, AppsDocumentEnvelopeReason, ""},
		{json.RawMessage(`{"_meta":null,"contents":[{"uri":"ui://widget","mimeType":"text/html;profile=mcp-app","text":"x"}]}`), minAppsDocumentBytes, AppsDocumentEnvelopeReason, ""},
		{json.RawMessage(`{"contents":[{"uri":"ui://widget","mimeType":"text/html;profile=mcp-app","_meta":[],"text":"x"}]}`), minAppsDocumentBytes, AppsDocumentEnvelopeReason, ""},
		{json.RawMessage(`{"unknown":1,"contents":[]}`), minAppsDocumentBytes, AppsDocumentEnvelopeReason, ""}, {json.RawMessage(`{"contents":[{"uri":"ui://widget","mimeType":"text/html;profile=mcp-app","name":"link","text":"x"}]}`), minAppsDocumentBytes, AppsDocumentEnvelopeReason, ""},
		{json.RawMessage(`{"contents":[{"uri":"ui://other","mimeType":"text/html;profile=mcp-app","text":"x"}]}`), minAppsDocumentBytes, AppsDocumentEnvelopeReason, ""}, {json.RawMessage(`{"contents":[{"uri":"ui://widget","mimeType":"text/html","text":"x"}]}`), minAppsDocumentBytes, AppsDocumentEnvelopeReason, ""},
		{json.RawMessage(`{"contents":[{"uri":"ui://widget","mimeType":"text/html;profile=mcp-app"}]}`), minAppsDocumentBytes, AppsDocumentEnvelopeReason, ""},
		{json.RawMessage(`{"contents":[}`), minAppsDocumentBytes, AppsDocumentEnvelopeReason, ""}, {json.RawMessage(`{"_meta":` + deepMeta + `,"contents":[]}`), minAppsDocumentBytes, AppsDocumentEnvelopeReason, ""},
		{json.RawMessage(`{"_meta":{"` + strings.Repeat("k", maxAppsJSONKeyBytes+1) + `":1},"contents":[]}`), minAppsDocumentBytes, AppsDocumentEnvelopeReason, ""},
		{invalidTopUTF8, minAppsDocumentBytes, AppsDocumentEnvelopeReason, ""}, {invalidContentUTF8, minAppsDocumentBytes, AppsDocumentEnvelopeReason, ""}, {tooManyTokens, minAppsDocumentBytes, AppsDocumentEnvelopeReason, ""},
		{appsDocumentRaw("text", textBody, ""), minAppsDocumentBytes - 1, AppsDocumentPolicyReason, ""}, {appsDocumentRaw("text", textBody, ""), maxAppsDocumentBytes + 1, AppsDocumentPolicyReason, ""},
		{appsDocumentRaw("text", boundary+"x", ""), minAppsDocumentBytes, AppsDocumentSizeReason, ""}, {appsDocumentRaw("blob", base64.StdEncoding.EncodeToString([]byte(boundary+"x")), ""), minAppsDocumentBytes, AppsDocumentSizeReason, ""},
		{appsDocumentRaw("blob", "%%%=", ""), minAppsDocumentBytes, AppsDocumentEncodingReason, "%%%="}, {appsDocumentRaw("blob", "AB==", ""), minAppsDocumentBytes, AppsDocumentEncodingReason, "AB=="}, {appsDocumentRaw("blob", "____", ""), minAppsDocumentBytes, AppsDocumentEncodingReason, "____"},
		{appsDocumentRaw("blob", "YQ", ""), minAppsDocumentBytes, AppsDocumentEncodingReason, "YQ"}, {appsDocumentRaw("blob", "YQ==\n", ""), minAppsDocumentBytes, AppsDocumentEncodingReason, "YQ=="},
		{appsDocumentRaw("blob", "YQ==AAAA", ""), minAppsDocumentBytes, AppsDocumentEncodingReason, "YQ=="}, {appsDocumentRaw("text", textBody, `,"blob":"YQ=="`), minAppsDocumentBytes, AppsDocumentEnvelopeReason, ""},
		{json.RawMessage(`{"contents":[{"uri":"ui://secret.example","mimeType":"text/html;profile=mcp-app","text":"x"}]}`), minAppsDocumentBytes, AppsDocumentEnvelopeReason, "ui://secret.example"},
	}
	for _, tc := range cases {
		_, err := decodeAppsDocument("ui://widget", tc.max, tc.raw)
		var typed *AppsDocumentError
		requireApps(t, errors.Is(err, ErrInvalidAppsDocument) && errors.As(err, &typed) && typed.Reason == tc.reason && (tc.secret == "" || !strings.Contains(err.Error(), tc.secret)))
	}
}

func appsDocumentRaw(field, body, extra string) json.RawMessage {
	value, err := json.Marshal(body)
	if err != nil {
		return nil
	}
	return json.RawMessage(`{"_meta":{"trace":{"ok":true}},"contents":[{"uri":"ui://widget","mimeType":"text/html;profile=mcp-app","` + field + `":` + string(value) + extra + `}]}`)
}

func TestAppsDocumentHTMLValidation(t *testing.T) {
	wrap := func(body string) string { return "<!doctype html><html><head></head><body>" + body + "</body></html>" }
	valid := []struct{ field, body string }{
		{"text", wrap("plain")}, {"blob", base64.StdEncoding.EncodeToString([]byte(wrap("blob")))},
		{"text", wrap("<img><br/><svg><path/></svg>")},
		{"text", "<!doctype html><!--a--><html><head><!--b--></head><body><!--c--></body></html><!--d-->"}, {"text", "\uFEFF" + wrap("bom")},
		{"text", wrap("<svg><foreignObject><div></div></foreignObject></svg><math><mi><mglyph/></mi></math>")},
	}
	for _, tc := range valid {
		metadata, err := ValidateAppsDocument("ui://widget", minAppsDocumentBytes, appsDocumentRaw(tc.field, tc.body, ""))
		requireApps(t, err == nil && metadata.DecodedSize > 0)
	}
	prefix, suffix := "<!doctype html><html><head></head><body><!--", "--></body></html>"
	exact := prefix + strings.Repeat("x", minAppsDocumentBytes-len(prefix)-len(suffix)) + suffix
	metadata, err := ValidateAppsDocument("ui://widget", minAppsDocumentBytes, appsDocumentRaw("text", exact, ""))
	requireApps(t, err == nil && metadata.DecodedSize == minAppsDocumentBytes)

	invalid := []string{
		"\uFEFF" + wrap("\uFEFF"), wrap("\x00"), wrap("\x01"), "<!--x-->" + wrap("x"),
		"<html><head></head><body></body></html>", "<!doctype svg><html><head></head><body></body></html>", "<!doctype html><html><body></body></html>", "<!doctype html><html><head></head></html>",
		"<!doctype html><html><body></body><head></head></html>", "<!doctype html><html><head></head><head></head><body></body></html>", "<!doctype html><html><head></head><body></body><body></body></html>",
		"<!doctype html><html><head></head><body></html></body>", "<!doctype html><html><head></head><body><div></body></html>",
		wrap(`<div A="1" a="2"></div>`), wrap(`<div a="1"b="2"></div>`), wrap("<div/>"), wrap("<p><div></div></p>"), wrap("<ul><li>x<li>y</li></li></ul>"),
		wrap("<table><div></div></table>"), wrap("x") + "tail", "<!doctype html><!--><html><head></head><body></body></html>",
		wrap(strings.Repeat("<div>", maxAppsHTMLDepth) + strings.Repeat("</div>", maxAppsHTMLDepth)),
		wrap(strings.Repeat("<!--x-->", maxAppsHTMLTokens+1)),
		wrap(strings.Repeat("<!--x-->", maxAppsHTMLNodes+1)),
	}
	attributes := make([]string, maxAppsHTMLAttributes+1)
	for i := range attributes {
		attributes[i] = " a" + strconv.Itoa(i) + `="x"`
	}
	invalid = append(invalid, wrap("<div"+strings.Join(attributes, "")+"></div>"))
	for _, body := range invalid {
		_, err := ValidateAppsDocument("ui://widget", minAppsDocumentBytes, appsDocumentRaw("text", body, ""))
		requireApps(t, appsHTMLDocumentError(err))
	}
	badUTF8 := base64.StdEncoding.EncodeToString([]byte{0xff, '<', 'h', 't', 'm', 'l', '>'})
	_, err = ValidateAppsDocument("ui://widget", minAppsDocumentBytes, appsDocumentRaw("blob", badUTF8, ""))
	requireApps(t, appsHTMLDocumentError(err))
	secret := wrap("unique-secret-content")
	_, err = ValidateAppsDocument("ui://widget", minAppsDocumentBytes, appsDocumentRaw("text", secret+"tail", ""))
	requireApps(t, !strings.Contains(err.Error(), secret))
}

func appsHTMLDocumentError(err error) bool {
	var typed *AppsDocumentError
	return errors.Is(err, ErrInvalidAppsDocument) && errors.As(err, &typed) && typed.Reason == AppsDocumentHTMLReason
}
