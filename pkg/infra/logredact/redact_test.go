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

package logredact

import (
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/auth"
)

func TestRedactLogString_BearerAndHeaders(t *testing.T) {
	in := "upstream failed: Authorization: Bearer sk-live-secret X-TG-API-Key: tgk_abc123"
	got := RedactLogString(in)
	if strings.Contains(got, "sk-live-secret") || strings.Contains(got, "tgk_abc123") {
		t.Fatalf("secrets leaked: %q", got)
	}
	if !strings.Contains(got, placeholder) {
		t.Fatalf("expected placeholder in %q", got)
	}
}

func TestRedactLogString_JSONInline(t *testing.T) {
	in := `decode failed body={"api_key":"sk-secret","model":"gpt-4o"}`
	got := RedactLogString(in)
	if strings.Contains(got, "sk-secret") {
		t.Fatalf("json credential leaked: %q", got)
	}
}

func TestRedactLogString_PreservesSafeText(t *testing.T) {
	in := "collector not found for gateway_id=abc"
	if got := RedactLogString(in); got != in {
		t.Fatalf("safe text altered: %q", got)
	}
}

func TestRedactLogString_ConsumerAPIKey(t *testing.T) {
	key, err := auth.GenerateAPIKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cases := map[string]string{
		"plain":       "consumer lookup failed for " + key + " on gateway gw-1",
		"query":       "GET /v1/models?key=" + key + "&limit=5",
		"quoted":      `rejected credential "` + key + `"`,
		"end of line": "key " + key,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			got := RedactLogString(in)
			if strings.Contains(got, key) || strings.Contains(got, key[3:]) {
				t.Fatalf("consumer key leaked: %q", got)
			}
			if !strings.Contains(got, placeholder) {
				t.Fatalf("expected placeholder in %q", got)
			}
		})
	}
}

func TestRedactLogString_ConsumerAPIKeyPrefixAloneIsKept(t *testing.T) {
	in := "flag_enabled=true ag_short tag_value=ok"
	if got := RedactLogString(in); got != in {
		t.Fatalf("non-key text altered: %q", got)
	}
}

func TestRedactLogString_OAuthJSONFields(t *testing.T) {
	fields := []string{
		"refresh_token", "id_token", "code_verifier", "subject_token",
		"actor_token", "client_assertion", "password",
	}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			in := `token exchange failed body={"` + field + `":"sensitive-value-123","grant_type":"x"}`
			got := RedactLogString(in)
			if strings.Contains(got, "sensitive-value-123") {
				t.Fatalf("%s leaked: %q", field, got)
			}
			if !strings.Contains(got, `"`+field+`": "`+placeholder+`"`) {
				t.Fatalf("expected %s to be redacted in place, got %q", field, got)
			}
			if !strings.Contains(got, `"grant_type":"x"`) {
				t.Fatalf("non-sensitive field altered: %q", got)
			}
		})
	}
}

func TestRedactLogString_FormEncodedFields(t *testing.T) {
	in := "token request failed: grant_type=refresh_token&refresh_token=rt-value&client_id=agw-1" +
		"&client_assertion=eyJ.assertion.sig&code_verifier=cv-value&subject_token=st-value" +
		"&actor_token=at-value&id_token=idt-value&password=pw-value&client_secret=cs-value"
	got := RedactLogString(in)
	for _, secret := range []string{"rt-value", "eyJ.assertion.sig", "cv-value", "st-value", "at-value", "idt-value", "pw-value", "cs-value"} {
		if strings.Contains(got, secret) {
			t.Fatalf("form value %q leaked: %q", secret, got)
		}
	}
	for _, kept := range []string{"grant_type=refresh_token", "client_id=agw-1", "refresh_token=" + placeholder} {
		if !strings.Contains(got, kept) {
			t.Fatalf("expected %q in %q", kept, got)
		}
	}
}
